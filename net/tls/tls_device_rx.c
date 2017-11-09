#include <net/tcp.h>
#include <net/inet_common.h>
#include <linux/highmem.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <crypto/aead.h>
#include <crypto/algapi.h>
#include <net/tls.h>
#include <net/sock.h>
#include <linux/sched/signal.h>

int decrypted;
module_param_named(rx_decrypted, decrypted, int, 0644);
int encrypted;
module_param_named(rx_encrypted, encrypted, int, 0644);

static inline u32 skb_offset(struct sk_buff *skb, u32 seq)
{
	u32 offset = seq - TCP_SKB_CB(skb)->seq;

	if ((s32)offset < 0) {
		pr_warn("check_seq: %u %u %u",
			seq, TCP_SKB_CB(skb)->seq, TCP_SKB_CB(skb)->end_seq);
		dump_stack();
	}
	return offset;
}

struct tcp_iterator {
	struct sk_buff *curr, *next, *end;
	u32 offset, available;
	u32 seq, remaining;
};

static inline bool tcp_iterator_next(struct tcp_iterator * it)
{
	int len = 0;

	while (len <= 0) {
		if (it->next == it->end)
			return false;

		it->curr = it->next;
		it->next = it->next->next;

		it->offset = skb_offset(it->curr, it->seq);
		len = it->curr->len - it->offset;
	}
	it->available = len;
	it->seq += len;
	return true;
}

static inline void tcp_iterator_init(struct tcp_iterator *it, u32 seq,
				     struct sk_buff_head *queue,
				     struct sk_buff *start)
{
	it->seq = seq;
	it->end = (struct sk_buff *)(queue);
	it->next = start ? start : queue->next;
}

#define TCP_ITERATOR_ON_STACK(name, seq, queue, start) \
	struct tcp_iterator __##name = {.seq = seq, \
					.end = (struct sk_buff *)(queue), \
					.next = start ? start : (queue)->next }, \
					*name = &__##name


static inline void copy_from_skb_list(struct sk_buff_head *list,
				      u32 seq, u8 *buf, u32 size)
{
	TCP_ITERATOR_ON_STACK(it, seq, list, NULL);

	while (tcp_iterator_next(it)) {
		u32 to_read = min(size, it->available);

		BUG_ON(skb_copy_bits(it->curr, it->offset, buf, to_read));
		buf += to_read;
		size -= to_read;
		if (!size)
			break;
	}
}

static inline u32 copy_decrypted_skbs_from_list(struct sk_buff_head *list,
						u32 seq, u8 *buf, u32 size)
{
	TCP_ITERATOR_ON_STACK(it, seq, list, NULL);
	u32 copied = 0;

	while (tcp_iterator_next(it)) {
		u32 to_read = min(size, it->available);

		if (it->curr->decrypted) {
			BUG_ON(skb_copy_bits(it->curr, it->offset, buf,
					to_read));
			copied += to_read;
		}
		buf += to_read;
		size -= to_read;
		if (!size)
			break;
	}

	return copied;
}

static inline void copy_encrypted_skbs_from_list(struct sk_buff_head *list,
						 u32 seq, u8 *buf, u32 size)
{
	TCP_ITERATOR_ON_STACK(it, seq, list, NULL);

	while (tcp_iterator_next(it)) {
		u32 to_read = min(size, it->available);

		if (!it->curr->decrypted)
			BUG_ON(skb_copy_bits(it->curr, it->offset, buf,
					     to_read));
		buf += to_read;

		if (it->available == to_read) {
			__skb_unlink(it->curr, list);
			__kfree_skb(it->curr);
		}
		size -= to_read;
		if (!size)
			break;
	}
}

static void recvmsg_cleanup(struct sock *sk, u32 seq)
{
	struct sk_buff *skb;

	while ((skb = skb_peek(&sk->sk_receive_queue)) != NULL) {
		if (after(TCP_SKB_CB(skb)->end_seq, seq))
			break;
		sk_eat_skb(sk, skb);
	}
}

int decrypt_record(struct sock *sk, u32 seq)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_rx_offload_context *ctx = tls_rx_offload_ctx(tls_ctx);

	unsigned int req_size = sizeof(struct aead_request) +
		crypto_aead_reqsize(ctx->rx_aead);
	struct aead_request *aead_req = kmalloc(req_size, GFP_KERNEL);
	struct scatterlist sg[1];
	u8 iv[TLS_CIPHER_AES_GCM_128_SALT_SIZE +
	      TLS_CIPHER_AES_GCM_128_IV_SIZE];
	u32 record_len = ctx->recv_record_end - seq;
	int tls_prepand = TLS_HEADER_SIZE + TLS_CIPHER_AES_GCM_128_IV_SIZE;
	int tls_overhead = tls_prepand + TLS_CIPHER_AES_GCM_128_TAG_SIZE;
	u32 data_len = record_len - tls_overhead;
	struct sk_buff *skb;
	struct page *page;
	u32 buf_len = data_len + TLS_AAD_SPACE_SIZE +
		      TLS_CIPHER_AES_GCM_128_TAG_SIZE;
	int order = get_order(buf_len);
	void *buf;
	int ret = -ENOMEM;
	__be64 rcd_sn;

	page = alloc_pages(GFP_KERNEL | __GFP_COMP, order);
	if (!page)
		return -ENOMEM;

	skb = alloc_skb(0, GFP_KERNEL);
	if (!skb) {
		put_page(page);
		return -ENOMEM;
	}

	skb->len = data_len + tls_prepand +
		   TLS_CIPHER_AES_GCM_128_TAG_SIZE;
	skb->data_len = skb->len;
	skb_fill_page_desc(skb, 0, page, TLS_AAD_SPACE_SIZE - tls_prepand,
			   skb->len);
	skb->truesize += 1 << (order + PAGE_SHIFT);
	skb_set_owner_r(skb, sk);

	TCP_SKB_CB(skb)->seq = seq;
	TCP_SKB_CB(skb)->end_seq = seq + record_len;

	seq += TLS_HEADER_SIZE;
	copy_from_skb_list(&sk->sk_receive_queue, seq,
			   iv + TLS_CIPHER_AES_GCM_128_SALT_SIZE,
			   TLS_CIPHER_AES_GCM_128_IV_SIZE);
	seq += TLS_CIPHER_AES_GCM_128_IV_SIZE;
	memcpy(iv, ctx->salt, TLS_CIPHER_AES_GCM_128_SALT_SIZE);

	sg_init_table(sg, 1);
	sg_set_page(sg, page, buf_len, TLS_AAD_SPACE_SIZE - tls_prepand);
	buf = page_to_virt(page);
	rcd_sn = cpu_to_be64(ctx->tls_record_sn);
	tls_make_aad(buf, data_len, (char *)&rcd_sn, sizeof(rcd_sn),
		     ctx->header[0]);

	if (tls_ctx->rx_conf == TLS_HW &&
	    copy_decrypted_skbs_from_list(&sk->sk_receive_queue, seq,
					  buf + TLS_AAD_SPACE_SIZE, data_len)) {
		/* encrypt encrypted payload in preparation
		 * for decrypt + authentication */
		aead_request_set_tfm(aead_req, ctx->rx_aead);
		aead_request_set_ad(aead_req, TLS_AAD_SPACE_SIZE);
		aead_request_set_crypt(aead_req, sg, sg,
				       data_len, iv);
		aead_request_set_callback(aead_req, 0, NULL, NULL);
		ret = crypto_aead_encrypt(aead_req);
		if (ret) {
			pr_err("encrypt failed %d\n", ret);
			kfree(aead_req);
			__kfree_skb(skb);
			return ret;
		}
	}

	copy_encrypted_skbs_from_list(&sk->sk_receive_queue, seq,
				      buf + TLS_AAD_SPACE_SIZE, data_len);
	seq += data_len;
	copy_from_skb_list(&sk->sk_receive_queue,
			   seq,
			   buf + TLS_AAD_SPACE_SIZE + data_len,
			   TLS_CIPHER_AES_GCM_128_TAG_SIZE);
	seq += TLS_CIPHER_AES_GCM_128_TAG_SIZE;
	recvmsg_cleanup(sk, seq);

	__skb_queue_head(&sk->sk_receive_queue, skb);

	/* decrypt the fully encrypted record */
	aead_request_set_tfm(aead_req, ctx->rx_aead);
	aead_request_set_ad(aead_req, TLS_AAD_SPACE_SIZE);
	aead_request_set_crypt(aead_req, sg, sg,
			       data_len + TLS_CIPHER_AES_GCM_128_TAG_SIZE, iv);
	aead_request_set_callback(aead_req, 0, NULL, NULL);

	ret = crypto_aead_decrypt(aead_req);
	kfree(aead_req);
	if (ret) {
		pr_err("decryption using iv %llu failed %d\n",
		       be64_to_cpu(*(__be64 *)
			          (iv + TLS_CIPHER_AES_GCM_128_SALT_SIZE)),
		       ret);

		/* store TLS prepend to allow retry in case the failure
		 * was due to ENOMEM
		 */
		memcpy(buf + TLS_AAD_SPACE_SIZE - tls_prepand,
		       ctx->header, TLS_HEADER_SIZE);
		memcpy(buf + TLS_AAD_SPACE_SIZE - TLS_CIPHER_AES_GCM_128_IV_SIZE,
		       iv + TLS_CIPHER_AES_GCM_128_SALT_SIZE,
		       TLS_CIPHER_AES_GCM_128_IV_SIZE);

		return ret;
	}

	pr_debug("decryption successful\n");
	return 0;
}

static int sk_wait_seq(struct sock *sk, long *timeo, u32 seq)
{
	int rc;
	DEFINE_WAIT_FUNC(wait, woken_wake_function);

	prepare_to_wait(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);
	sk_set_bit(SOCKWQ_ASYNC_WAITDATA, sk);
	rc = sk_wait_event(sk, timeo, !before(tcp_sk(sk)->rcv_nxt, seq), &wait);
	sk_clear_bit(SOCKWQ_ASYNC_WAITDATA, sk);
	finish_wait(sk_sleep(sk), &wait);
	return rc;
}

static int check_sk_state(struct sock *sk, long *timeo)
{
	if (sock_flag(sk, SOCK_DONE))
		return -ENOLINK;

	if (sk->sk_shutdown & RCV_SHUTDOWN)
		return -ENOLINK;

	if (sk->sk_state == TCP_CLOSE) {
		if (!sock_flag(sk, SOCK_DONE)) {
			/* This occurs when user tries to read
			 * from never connected socket.
			 */
			return -ENOTCONN;
		}
		return -ENOLINK;
	}

	if (!*timeo)
		return -EAGAIN;

	if (signal_pending(current))
		return -EINTR;

	return 0;
}

static int wait_for_seq(struct sock *sk, long *timeo, u32 seq)
{
	int ret;

	if (!before(tcp_sk(sk)->rcv_nxt, seq))
		return 0;

	if (!*timeo) {
		/* Do not sleep, just process backlog. */
		release_sock(sk);
		lock_sock(sk);

		if (!before(tcp_sk(sk)->rcv_nxt, seq))
			return 0;

		return -EAGAIN;
	}

	do {
		ret = check_sk_state(sk, timeo);
		if (ret)
			return ret;
	} while (!sk_wait_seq(sk, timeo, seq));

	return 0;
}

#define TLS_VERSION_VALUE (htonl((TLS_1_2_VERSION_MAJOR) << 16 | \
				 ((TLS_1_2_VERSION_MINOR) << 8)))
#define TLS_VERSION_MASK (htonl(((0xff) << 16) | (0xff << 8)))

static int proccess_record_header(u8 *header)
{
	u16 record_len;
	u32 header_dword;

	memcpy(&header_dword, header, sizeof(u32));
	if (unlikely((header_dword ^ TLS_VERSION_VALUE) & TLS_VERSION_MASK)) {
		pr_info("bad record header %x\n",
			htonl(header_dword));
		return -EINVAL;
	}

#ifdef CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS
	memcpy(&record_len, header + 3, sizeof(u16));
	record_len = ntohs(record_len);
#else
	record_len = header[4] | (header[3] << 8);
#endif
	pr_debug("record len %u\n", record_len);
	record_len += TLS_HEADER_SIZE;
	if (record_len < TLS_MIN_RECORD_SIZE)
		return -EINVAL;

	return record_len;
}

/* Caller is responsible from making sure start and end are valid */
static int tls_proccess_headers(struct sock *sk, u32 start, u32 end,
				u32 *last_record_seq, u64 *records_count)
{
	u32 seq = start;
	u64 count = 0;
	u8 header[TLS_HEADER_SIZE];
	int ret;
	struct sk_buff *skb = sk->sk_receive_queue.next;

	while ((end - seq) >= TLS_HEADER_SIZE) {
		TCP_ITERATOR_ON_STACK(it, seq, &sk->sk_receive_queue, skb);
		u32 size = ARRAY_SIZE(header);
		void *buf = header;

		while (tcp_iterator_next(it)) {
			u32 to_read = min(size, it->available);

			skb = it->curr;
			if (skb_copy_bits(skb, it->offset, buf, to_read)) {
				pr_warn("skb_copy_bits failed offset = %u len=%u to_read=%u\n",
					it->offset, skb->len, to_read);
				goto out;
			}
			buf += to_read;
			size -= to_read;
			if (!size)
				break;
		}

		ret = proccess_record_header(header);
		if (ret < 0)
			return ret;

		seq += ret;
		count++;
	}

out:
	*records_count = count;
	*last_record_seq = seq;
	return 0;
}

int tls_get_start_sn(struct sock *sk, u32 *start, u64 *p_count)
{
	struct tcp_sock *tp = tcp_sk(sk);

	return tls_proccess_headers(sk, tp->copied_seq, tp->rcv_nxt, start,
				    p_count);
}
EXPORT_SYMBOL(tls_get_start_sn);

static int tls_get_record_sn(struct sock *sk,
			     struct tls_rx_offload_context *ctx, u32 seq,
			     u64 *p_rcd_sn)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 found_seq;
	u64 count;

	if (after(seq, tp->rcv_nxt))
		return -EINVAL;

	if (before(seq, ctx->recv_record_end))
		return -EINVAL;

	if (tls_proccess_headers(sk, ctx->recv_record_end, seq, &found_seq,
				 &count) ||
	    found_seq != seq)
		return -EINVAL;

	/* recv_record_end marks the beginning of the
	 * record with sn tls_record_sn + 1.
	 */
	*p_rcd_sn = ctx->tls_record_sn + 1 + count;
	return 0;
}

static inline void do_resync(struct tls_context *tls_ctx, u32 seq, u64 rcd_sn)
{
	struct tls_rx_offload_context *ctx = tls_rx_offload_ctx(tls_ctx);

	ctx->rx_sync_callback(tls_ctx, seq, rcd_sn);
}

static void get_record_header(struct sock *sk, u32 seq, u8 *buf,
			      struct tls_rx_offload_context *ctx)
{
	u32 size = TLS_HEADER_SIZE;
	TCP_ITERATOR_ON_STACK(it, seq, &sk->sk_receive_queue, NULL);

	while (tcp_iterator_next(it)) {
		u32 to_read = min(size, it->available);

		BUG_ON(skb_copy_bits(it->curr, it->offset, buf, to_read));
		buf += to_read;

		size -= to_read;
		if (!size)
			break;
	}
}

static void handle_resync(struct tls_rx_offload_context *ctx, struct sock *sk)
{
	s64 resync_req = atomic64_read(&ctx->resync_req);
	u32 req = resync_req;
	u32 req_seq = resync_req >> 32;
	u64 rcd_sn;

	if (unlikely(req) && !after(req_seq, tcp_sk(sk)->rcv_nxt) &&
	    atomic64_try_cmpxchg(&ctx->resync_req, &resync_req, 0) &&
	    !tls_get_record_sn(sk, ctx, req_seq, &rcd_sn))
		do_resync(tls_get_ctx(sk), req_seq, rcd_sn);

}

static int wait_for_record(struct tls_rx_offload_context *ctx,
			   struct sock *sk, u32 seq, long *timeo)
{
	int ret;

	if (seq == ctx->recv_record_end) {
		ret = wait_for_seq(sk, timeo, seq + (u32)TLS_HEADER_SIZE - 1);
		if (ret)
			return ret;

		handle_resync(ctx, sk);

		get_record_header(sk, seq, ctx->header, ctx);

		ret = proccess_record_header(ctx->header);
		if (ret < 0)
			return ret;
		ctx->recv_record_end += ret;
	}

	return wait_for_seq(sk, timeo, ctx->recv_record_end);
}

static bool tls_record_need_decryption(struct tls_rx_offload_context *ctx,
				       struct sock *sk, u32 record_start_seq)
{
	u32 seq = record_start_seq;
	TCP_ITERATOR_ON_STACK(it, seq, &sk->sk_receive_queue, NULL);

	while (tcp_iterator_next(it)) {
		struct sk_buff *skb = it->curr;

		pr_debug("tls_validate_record %p [%u-%u) %u %s\n", skb,
			 TCP_SKB_CB(skb)->seq, TCP_SKB_CB(skb)->end_seq, seq,
			 skb->decrypted ? "decrypted" : "encrypted");

		if (!skb->decrypted)
			return true;

		if (!before(TCP_SKB_CB(skb)->end_seq, ctx->recv_record_end))
			break;
	}

	return false;
}

static int copy_record_to_user(struct sk_buff_head *list, u32 seq,
			       struct msghdr *msg, u32 size,
			       size_t *p_copied)
{
	TCP_ITERATOR_ON_STACK(it, seq, list, NULL);
	int ret = 0;
	size_t copied = 0;

	while (tcp_iterator_next(it)) {
		u32 to_read = min(size, it->available);

		ret = skb_copy_datagram_msg(it->curr, it->offset, msg, to_read);
		if (ret) {
			pr_err("copy to user failed %d\n", ret);
			copied = 0;
			break;
		}

		/* Can't free SKBs here as copy_to_user might
		 * fail during this record
		 */

		copied += to_read;
		size -= to_read;
		if (!size)
			break;
	}

	*p_copied = copied;
	return ret;
}

int tls_cmsg_set_record_type(struct msghdr *msg,
			     unsigned char record_type)
{
	struct cmsghdr *cmsg;
	int rc = -EINVAL;

	for_each_cmsghdr(cmsg, msg) {
		if (!CMSG_OK(msg, cmsg))
			return -EINVAL;
		if (cmsg->cmsg_level != SOL_TLS)
			continue;

		switch (cmsg->cmsg_type) {
		case TLS_GET_RECORD_TYPE:
			if (cmsg->cmsg_len < CMSG_LEN(sizeof(record_type)))
				return -EINVAL;
			memcpy(CMSG_DATA(cmsg), &record_type,
			       sizeof(record_type));
			rc = 0;
			break;
		default:
			return -EINVAL;
		}
	}

	return rc;
}

int tls_recvmsg(struct sock *sk, struct msghdr *msg, size_t user_len,
		int noblock, int flags, int *addr_len)
{
	int ret = 0;
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_rx_offload_context *ctx = tls_rx_offload_ctx(tls_ctx);
	struct tcp_sock *tp = tcp_sk(sk);
	u32 seq;
	size_t to_read, copied = 0;
	size_t orig_user_len = user_len;
	size_t target;
	long timeo = sock_rcvtimeo(sk, noblock);
	int tls_prepand = TLS_HEADER_SIZE + TLS_CIPHER_AES_GCM_128_IV_SIZE;

	pr_debug("%s started\n", __func__);

	if (sk->sk_err)
		return sk->sk_err;

	/* Set record type to TLS_RECORD_TYPE_DATA
	 * This is overwritten later in case it is wrong
	 */
	tls_cmsg_set_record_type(msg, TLS_RECORD_TYPE_DATA);

	lock_sock(sk);
	target = sock_rcvlowat(sk, flags & MSG_WAITALL, user_len);
	seq = tp->copied_seq;
	while (user_len) {
		if (!(ctx->record_ready)) {
			ret = wait_for_record(ctx, sk, seq, &timeo);
			if (ret) {
				if (orig_user_len != user_len)
					break;

				switch (ret) {
				case -EINTR:
					ret = sock_intr_errno(timeo);
					break;
				case -EAGAIN:
					break;
				case -ENOLINK:
					ret = 0;
					break;
				default:
					break;
				}

				break;
			}

			if (tls_record_need_decryption(ctx, sk, seq)) {
				ret = decrypt_record(sk, seq);
				if (ret) {
					if (ret != -ENOMEM) {
						sk->sk_err = ret;
					}
					break;
				}
				encrypted++;
			} else
				decrypted++;

			seq += tls_prepand;
			ctx->record_ready = 1;
		}

		if (unlikely(ctx->header[0] != TLS_RECORD_TYPE_DATA)) {
			to_read = ctx->recv_record_end - seq -
				  TLS_CIPHER_AES_GCM_128_TAG_SIZE;

			/* Record type != TLS_RECORD_TYPE_DATA
			 * can be returned to the user only if
			 *  1. There is enough room for the entire alert
			 *  2. We didn't copy anything else during this call
			 *  3. We were called with
			 *     cmsg_type == TLS_GET_RECORD_TYPE
			 */
			if (to_read > user_len ||
			    orig_user_len > user_len ||
			    tls_cmsg_set_record_type(msg, ctx->header[0])) {
				ret = -ESTRPIPE;
				goto skip_copy;
			}

			/* stop copy after alert record */
			flags |= MSG_EOR;
		}

		to_read = min((size_t)(ctx->recv_record_end - seq -
				       TLS_CIPHER_AES_GCM_128_TAG_SIZE),
			      user_len);

		pr_debug("copying %zu\n", to_read);
		ret = copy_record_to_user(&sk->sk_receive_queue, seq, msg,
					  to_read, &copied);
		if (!copied) {
			if (WARN(!ret,
				"copy_record_to_user failed with no error rcv queue len = %u\n",
				 skb_queue_len(&sk->sk_receive_queue)))
				ret = -EFAULT;
			break;
		}

		user_len -= copied;
		seq += copied;
		if (ctx->recv_record_end - seq ==
		    TLS_CIPHER_AES_GCM_128_TAG_SIZE) {
			seq = ctx->recv_record_end;
			ctx->record_ready = 0;
			pr_debug("record %llu completed\n",
				 ctx->tls_record_sn);
			ctx->tls_record_sn++;

			if (orig_user_len - user_len > target) {
				/* we read enough data so
				 * no more blocking
				 */
				timeo = 0;
			}

			/* If MSG_EOR is set, set ret to an error value
			 * in order to stop at the end of the record.
			 * Note that orig_user_len - user_len > 0
			 * so we will return the amount of byte copy
			 * and not the error value below.
			 */
			if (flags & MSG_EOR)
				ret = -EINTR;
		}

skip_copy:
		tp->copied_seq = seq;
		recvmsg_cleanup(sk, seq);
		tcp_rcv_space_adjust(sk);
		tcp_cleanup_rbuf(sk, copied);

		if (!user_len || ret)
			break;
	}

	release_sock(sk);
	copied = orig_user_len - user_len;
	if (copied > 0)
		return copied;

	return ret;
}
EXPORT_SYMBOL(tls_recvmsg);
MODULE_LICENSE("GPL");
