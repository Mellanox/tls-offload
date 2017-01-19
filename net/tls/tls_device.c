/* Copyright (c) 2016-2017, Mellanox Technologies All rights reserved.
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 *      - Neither the name of the Mellanox Technologies nor the
 *        names of its contributors may be used to endorse or promote
 *        products derived from this software without specific prior written
 *        permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE
 */

#include <linux/module.h>
#include <net/tcp.h>
#include <net/inet_common.h>
#include <linux/highmem.h>
#include <linux/netdevice.h>

#include <net/tls.h>

/* We assume that the socket is already connected */
static struct net_device *get_netdev_for_sock(struct sock *sk)
{
	struct inet_sock *inet = inet_sk(sk);
	struct net_device *netdev = NULL;

	pr_info("Using output interface 0x%x\n", inet->cork.fl.flowi_oif);
	netdev = dev_get_by_index(sock_net(sk), inet->cork.fl.flowi_oif);

	return netdev;
}

static void detach_sock_from_netdev(struct sock *sk, struct tls_context *ctx)
{
	struct net_device *netdev;

	netdev = get_netdev_for_sock(sk);
	if (!netdev) {
		pr_err("got offloaded socket with no netdev");
		return;
	}

	if (!netdev->tlsdev_ops) {
		pr_err("attach_sock_to_netdev: netdev %s with no TLS offload\n",
		       netdev->name);
		return;
	}

	netdev->tlsdev_ops->tls_dev_del(netdev, sk, true);
	dev_put(netdev);
}

static int attach_sock_to_netdev(struct sock *sk, struct tls_context *ctx)
{
	struct net_device *netdev = get_netdev_for_sock(sk);
	int rc = -EINVAL;

	if (!netdev) {
		pr_err("attach_sock_to_netdev: netdev not found\n");
		goto out;
	}

	if (!netdev->tlsdev_ops) {
		pr_err("attach_sock_to_netdev: netdev %s with no TLS offload\n",
		       netdev->name);
		goto out;
	}

	rc = netdev->tlsdev_ops->tls_dev_add(netdev, sk, true,
			&ctx->crypto_send, &ctx->offload_ctx);
	if (rc) {
		pr_err("The netdev has refused to offload this socket\n");
		goto out;
	}

	sk->sk_bound_dev_if = netdev->ifindex;
	sk_dst_reset(sk);

	rc = 0;
out:
	dev_put(netdev);
	return rc;
}

static void destroy_record(struct tls_record_info *record)
{
	skb_frag_t *frag;
	int nr_frags = record->num_frags;

	while (nr_frags > 0) {
		frag = &record->frags[nr_frags - 1];
		__skb_frag_unref(frag);
		--nr_frags;
	}
	kfree(record);
}

static void delete_all_records(struct tls_offload_context *offload_ctx)
{
	struct tls_record_info *info, *temp;

	list_for_each_entry_safe(info, temp, &offload_ctx->records_list, list) {
		list_del(&info->list);
		destroy_record(info);
	}
}

void tls_clear_device_offload(struct sock *sk, struct tls_context *ctx)
{
	struct tls_offload_context *offload_ctx = ctx->offload_ctx;

	if (!offload_ctx)
		return;

	delete_all_records(offload_ctx);
	detach_sock_from_netdev(sk, ctx);
	kfree(offload_ctx->iv);
}

void tls_icsk_clean_acked(struct sock *sk)
{
	struct tls_context *ctx = sk->sk_user_data;
	struct tls_offload_context *offload_ctx;
	struct tcp_sock *tp = tcp_sk(sk);
	struct tls_record_info *info, *temp;
	unsigned long flags;

	if (!ctx)
		return;

	offload_ctx = ctx->offload_ctx;

	spin_lock_irqsave(&offload_ctx->lock, flags);
	info = offload_ctx->retransmit_hint;
	if (info && !before(tp->snd_una, info->end_seq)) {
		offload_ctx->retransmit_hint = NULL;
		list_del(&info->list);
		destroy_record(info);
	}

	list_for_each_entry_safe(info, temp, &offload_ctx->records_list, list) {
		if (before(tp->snd_una, info->end_seq))
			break;
		list_del(&info->list);

		destroy_record(info);
	}

	spin_unlock_irqrestore(&offload_ctx->lock, flags);
}
EXPORT_SYMBOL(tls_icsk_clean_acked);

int tls_set_device_offload(struct sock *sk, struct tls_context *ctx)
{
	struct tls_crypto_info *crypto_info;
	struct tls_offload_context *offload_ctx;
	struct tls_record_info *dummy_record;
	u16 nonece_size, tag_size, iv_size;
	char *iv;
	int rc;

	if (!ctx) {
		rc = -EINVAL;
		goto out;
	}

	if (ctx->offload_ctx) {
		rc = -EEXIST;
		goto out;
	}

	crypto_info = &ctx->crypto_send;
	switch (crypto_info->cipher_type) {
	case TLS_CIPHER_AES_GCM_128: {
		nonece_size = TLS_CIPHER_AES_GCM_128_IV_SIZE;
		tag_size = TLS_CIPHER_AES_GCM_128_TAG_SIZE;
		iv_size = TLS_CIPHER_AES_GCM_128_IV_SIZE;
		iv = ((struct tls_crypto_info_aes_gcm_128 *)crypto_info)->iv;
		break;
	}
	default:
		rc = -EINVAL;
		goto out;
	}

	dummy_record = kmalloc(sizeof(*dummy_record), GFP_KERNEL);
	if (!dummy_record) {
		rc = -ENOMEM;
		goto out;
	}

	rc = attach_sock_to_netdev(sk, ctx);
	if (rc)
		goto err_dummy_record;

	offload_ctx = ctx->offload_ctx;
	offload_ctx->prepand_size = TLS_HEADER_SIZE + nonece_size;
	offload_ctx->tag_size = tag_size;
	offload_ctx->iv_size = iv_size;
	offload_ctx->iv = kmalloc(iv_size, GFP_KERNEL);
	if (!offload_ctx->iv) {
		rc = ENOMEM;
		goto detach_sock;
	}
	memcpy(offload_ctx->iv, iv, iv_size);

	dummy_record->end_seq = offload_ctx->expectedSN;
	dummy_record->len = 0;
	dummy_record->num_frags = 0;

	INIT_LIST_HEAD(&offload_ctx->records_list);
	list_add_tail(&dummy_record->list, &offload_ctx->records_list);
	spin_lock_init(&offload_ctx->lock);
	ctx->offload_ctx = offload_ctx;

	/* After this line the tx_handler might access the offload context */
	smp_store_release(&inet_csk(sk)->icsk_clean_acked,
			  &tls_icsk_clean_acked);
	goto out;

detach_sock:
	detach_sock_from_netdev(sk, ctx);
err_dummy_record:
	kfree(dummy_record);
out:
	return rc;
}

static inline int tls_send_record(struct sock *sk,
				  struct tls_offload_context *offload_ctx,
				  struct tls_record_info *record,
				  int more)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int i = 0;
	skb_frag_t *frag;
	int flags = MSG_SENDPAGE_NOTLAST;
	int ret = 0;

	record->end_seq = tp->write_seq + record->len;

	spin_lock_irq(&offload_ctx->lock);
	list_add_tail(&record->list, &offload_ctx->records_list);
	spin_unlock_irq(&offload_ctx->lock);

	do  {
		frag = &record->frags[i];
		i++;
		if (i == record->num_frags && !more)
			flags = 0;

		 /* is sending application-limited? */
		tcp_rate_check_app_limited(sk);
		ret = do_tcp_sendpages(sk,
				       skb_frag_page(frag),
				       frag->page_offset,
				       skb_frag_size(frag),
				       flags);

		if (ret != skb_frag_size(frag)) {
			pr_err("do_tcp_sendpages sent only part of the frag ret=%d",
			       ret);
			if (ret >= 0)
				return -EPIPE;
		}
	} while (i < record->num_frags);

	return 0;
}

static void tls_fill_prepend(struct tls_crypto_info *crypto_info,
			     struct tls_offload_context *offload_ctx,
			     char *buf,
			     size_t plaintext_len)
{
	size_t pkt_len, iv_size = offload_ctx->iv_size;

	pkt_len = plaintext_len + iv_size + offload_ctx->tag_size;

	/* we cover nonce explicit here as well, so buf should be of
	 * size KTLS_DTLS_HEADER_SIZE + KTLS_DTLS_NONCE_EXPLICIT_SIZE
	 */
	buf[0] = TLS_RECORD_TYPE_DATA;
	buf[1] = TLS_VERSION_MINOR(crypto_info->version);
	buf[2] = TLS_VERSION_MAJOR(crypto_info->version);
	/* we can use IV for nonce explicit according to spec */
	buf[3] = pkt_len >> 8;
	buf[4] = pkt_len & 0xFF;
	memcpy(buf + TLS_NONCE_OFFSET, offload_ctx->iv, iv_size);
}

static inline void tls_err_abort(struct sock *sk)
{
	xchg(&sk->sk_err, -EBADMSG);
	sk->sk_error_report(sk);
}

static inline void tls_increment_seqno(unsigned char *seq, struct sock *sk)
{
	int i;

	for (i = 7; i >= 0; i--) {
		++seq[i];
		if (seq[i] != 0)
			break;
	}

	if (i == -1)
		tls_err_abort(sk);
}

static inline void tls_append_frag(struct tls_record_info *record,
				   struct page_frag *pfrag,
				   int size)
{
	skb_frag_t *frag;

	frag = &record->frags[record->num_frags - 1];
	if (frag->page.p == pfrag->page &&
	    frag->page_offset + frag->size == pfrag->offset) {
		frag->size += size;
	} else {
		++frag;
		frag->page.p = pfrag->page;
		frag->page_offset = pfrag->offset;
		frag->size = size;
		++record->num_frags;
		get_page(pfrag->page);
	}

	pfrag->offset += size;
	record->len += size;
}

static inline int tls_push_record(struct sock *sk,
				  struct tls_crypto_info *crypto_info,
				  struct tls_offload_context *offload_ctx,
				  struct tls_record_info *record,
				  struct page_frag *pfrag,
				  int more)
{
	int ret;
	skb_frag_t *frag;

	/* fill prepand */
	frag = &record->frags[0];
	tls_fill_prepend(crypto_info,
			 offload_ctx,
			 skb_frag_address(frag),
			 record->len - offload_ctx->prepand_size);
	frag = &record->frags[record->num_frags];

	if (!skb_page_frag_refill(offload_ctx->tag_size, pfrag, GFP_KERNEL))
		return -ENOMEM;

	tls_append_frag(record, pfrag, offload_ctx->tag_size);

	/* all ready, send */
	ret = tls_send_record(sk, offload_ctx, record, more);
	if (ret >= 0)
		tls_increment_seqno(offload_ctx->iv, sk);

	return ret;
}

static inline struct tls_record_info *tls_get_open_new_record(
		struct tls_offload_context *offload_ctx,
		struct page_frag *pfrag,
		size_t prepand_size)
{
	skb_frag_t *frag;
	struct tls_record_info *record;

	if (offload_ctx->open_record)
		return offload_ctx->open_record;

	/* TODO: do we want to use pfrag
	 * to store the record metadata?
	 * the lifetime of the data and
	 * metadata is the same and
	 * we can avoid kmalloc overhead.
	 */
	record = kmalloc(sizeof(*record), GFP_KERNEL);
	if (!record)
		return NULL;

	frag = &record->frags[0];
	__skb_frag_set_page(frag, pfrag->page);
	frag->page_offset = pfrag->offset;
	skb_frag_size_set(frag, prepand_size);

	get_page(pfrag->page);
	pfrag->offset += prepand_size;

	record->num_frags = 1;
	record->len = prepand_size;
	offload_ctx->open_record = record;
	return record;
}

static int tls_push_data(struct sock *sk,
			 struct iov_iter *msg_iter,
			 size_t size, int more)
{
	struct tls_context *ctx = sk->sk_user_data;
	struct tls_offload_context *offload_ctx = ctx->offload_ctx;
	struct tls_crypto_info *crypto_info = &ctx->crypto_send;
	struct tls_record_info *record = offload_ctx->open_record;
	struct page_frag *pfrag = &current->task_frag;
	int copy, rc = 0;
	size_t orig_size = size;
	u32 max_open_record_len;

	if (sk->sk_err)
		return sk->sk_err;

	/* Only one writer at a time is allowed */
	if (sk->sk_write_pending)
		return -EBUSY;

	/* KTLS_TLS_HEADER_SIZE is not counted as part of the TLS record, and
	 * we need to leave room for an authentication tag.
	 */
	max_open_record_len = TLS_MAX_PAYLOAD_SIZE
			+ TLS_HEADER_SIZE - offload_ctx->tag_size;

	do {
		/* get record */
		if (!skb_page_frag_refill(32, pfrag, GFP_KERNEL) ||
		    !(tls_get_open_new_record(offload_ctx,
					      pfrag,
					      offload_ctx->prepand_size))) {
			rc = -ENOMEM;
			break;
		}
		record = tls_get_open_new_record(offload_ctx,
						 pfrag,
						 offload_ctx->prepand_size);

		/* payload */
		copy = min3(size, (size_t)(pfrag->size - pfrag->offset),
			    (size_t)(max_open_record_len - record->len));
		if (copy_from_iter_nocache(
				page_address(pfrag->page) + pfrag->offset,
				copy, msg_iter) != copy) {
			rc = -EFAULT;
			break;
		}
		tls_append_frag(record, pfrag, copy);

		if ((record->len >= max_open_record_len) ||
		    (!more && (size == copy)) ||
		    (record->num_frags >= MAX_SKB_FRAGS - 1)) {
			rc = tls_push_record(sk,
					     crypto_info,
					     offload_ctx,
					     record,
					     pfrag,
					     more);
			offload_ctx->open_record = NULL;
			if (rc < 0) {
				pr_err("tls_push_record failed %d\n", rc);
				sk->sk_err = rc;
				break;
			}
		}

		size -= copy;
	} while (size);

	if (orig_size - size > 0)
		rc = orig_size - size;

	return rc;
}

int tls_sendmsg_with_offload(struct sock *sk, struct msghdr *msg,
			     size_t size)
{
	return tls_push_data(sk, &msg->msg_iter, size,
			     msg->msg_flags & MSG_MORE);
}

int tls_sendpage_with_offload(struct sock *sk, struct page *page,
			      int offset, size_t size, int flags)
{
	struct iov_iter	msg_iter;
	struct kvec iov;
	char *kaddr = kmap(page);
	int rc;

	iov.iov_base = kaddr + offset;
	iov.iov_len = size;
	iov_iter_kvec(&msg_iter, WRITE | ITER_KVEC, &iov, 1, size);
	rc = tls_push_data(sk, &msg_iter, size,
			   flags & (MSG_SENDPAGE_NOTLAST | MSG_MORE));
	kunmap(page);
	return rc;
}

struct tls_record_info *tls_get_record(struct tls_offload_context *context,
				       u32 seq)
{
	struct tls_record_info *info;

	info = context->retransmit_hint;
	if (!info ||
	    before(seq, info->end_seq - info->len))
		info = list_first_entry(&context->records_list,
					struct tls_record_info, list);

	list_for_each_entry_from(info, &context->records_list, list) {
		if (before(seq, info->end_seq)) {
			if (!context->retransmit_hint ||
			    after(info->end_seq,
				  context->retransmit_hint->end_seq))
				context->retransmit_hint = info;
			return info;
		}
	}

	return NULL;
}
EXPORT_SYMBOL(tls_get_record);
