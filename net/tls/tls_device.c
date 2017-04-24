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
		pr_err("got offloaded socket with no netdev\n");
		return;
	}

	if (!netdev->tlsdev_ops) {
		pr_err("attach_sock_to_netdev: netdev %s with no TLS offload\n",
		       netdev->name);
		return;
	}

	netdev->tlsdev_ops->tls_dev_del(netdev, sk, TLS_OFFLOAD_CTX_DIR_TX);
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

	rc = netdev->tlsdev_ops->tls_dev_add(
			netdev,
			sk,
			TLS_OFFLOAD_CTX_DIR_TX,
			&ctx->crypto_send,
			(struct tls_offload_context **)(&ctx->priv_ctx));
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

void tls_clear_device_offload(struct sock *sk, struct tls_context *tls_ctx)
{
	struct tls_offload_context *ctx = tls_offload_ctx(tls_ctx);

	if (!ctx)
		return;

	if (ctx->open_record)
		destroy_record(ctx->open_record);

	delete_all_records(ctx);
	detach_sock_from_netdev(sk, tls_ctx);
}

void tls_icsk_clean_acked(struct sock *sk)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_offload_context *ctx;
	struct tcp_sock *tp = tcp_sk(sk);
	struct tls_record_info *info, *temp;
	unsigned long flags;

	if (!tls_ctx)
		return;

	ctx = tls_offload_ctx(tls_ctx);

	spin_lock_irqsave(&ctx->lock, flags);
	info = ctx->retransmit_hint;
	if (info && !before(tp->snd_una, info->end_seq)) {
		ctx->retransmit_hint = NULL;
		list_del(&info->list);
		destroy_record(info);
	}

	list_for_each_entry_safe(info, temp, &ctx->records_list, list) {
		if (before(tp->snd_una, info->end_seq))
			break;
		list_del(&info->list);

		destroy_record(info);
	}

	spin_unlock_irqrestore(&ctx->lock, flags);
}
EXPORT_SYMBOL(tls_icsk_clean_acked);

void tls_device_sk_destruct(struct sock *sk)
{
	struct tls_context *ctx = tls_get_ctx(sk);

	tls_clear_device_offload(sk, ctx);
	tls_sk_destruct(sk, ctx);
}
EXPORT_SYMBOL(tls_device_sk_destruct);

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
				  struct tls_context *ctx,
				  struct tls_offload_context *offload_ctx,
				  struct tls_record_info *record,
				  struct page_frag *pfrag,
				  int flags,
				  unsigned char record_type)
{
	skb_frag_t *frag;
	struct tcp_sock *tp = tcp_sk(sk);
	struct page_frag fallback_frag;
	struct page_frag  *tag_pfrag = pfrag;

	/* fill prepand */
	frag = &record->frags[0];
	tls_fill_prepend(ctx,
			 skb_frag_address(frag),
			 record->len - ctx->prepand_size,
			 record_type);

	if (unlikely(!skb_page_frag_refill(
				ctx->tag_size,
				pfrag, GFP_KERNEL))) {
		/* HW doesn't care about the data in the tag
		 * so in case pfrag has no room
		 * for a tag and we can't allocate a new pfrag
		 * just use the page in the first frag
		 * rather then write a complicated fall back code.
		 */
		tag_pfrag = &fallback_frag;
		tag_pfrag->page = skb_frag_page(frag);
		tag_pfrag->offset = 0;
	}

	tls_append_frag(record, tag_pfrag, ctx->tag_size);
	record->end_seq = tp->write_seq + record->len;
	spin_lock_irq(&offload_ctx->lock);
	list_add_tail(&record->list, &offload_ctx->records_list);
	spin_unlock_irq(&offload_ctx->lock);

	offload_ctx->open_record = NULL;
	tls_increment_seqno(ctx->iv, sk);

	/* all ready, send */
	return tls_push_frags(sk, ctx, record->frags,
			      record->num_frags, 0, flags);

}

static inline int tls_get_new_record(
		struct tls_offload_context *offload_ctx,
		struct page_frag *pfrag,
		size_t prepand_size)
{
	skb_frag_t *frag;
	struct tls_record_info *record;

	/* TODO: do we want to use pfrag
	 * to store the record metadata?
	 * the lifetime of the data and
	 * metadata is the same and
	 * we can avoid kmalloc overhead.
	 */
	record = kmalloc(sizeof(*record), GFP_KERNEL);
	if (!record)
		return -ENOMEM;

	frag = &record->frags[0];
	__skb_frag_set_page(frag, pfrag->page);
	frag->page_offset = pfrag->offset;
	skb_frag_size_set(frag, prepand_size);

	get_page(pfrag->page);
	pfrag->offset += prepand_size;

	record->num_frags = 1;
	record->len = prepand_size;
	offload_ctx->open_record = record;
	return 0;
}

static inline int tls_do_allocation(
		struct sock *sk,
		struct tls_offload_context *offload_ctx,
		struct page_frag *pfrag,
		size_t prepand_size)
{
	struct tls_record_info *record;

	if (!sk_page_frag_refill(sk, pfrag))
		return -ENOMEM;

	record = offload_ctx->open_record;
	if (!record) {
		tls_get_new_record(offload_ctx, pfrag, prepand_size);
		record = offload_ctx->open_record;
		if (!record)
			return -ENOMEM;
	}

	return 0;
}

static int tls_push_data(struct sock *sk,
			 struct iov_iter *msg_iter,
			 size_t size, int flags,
			 unsigned char record_type)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_offload_context *ctx = tls_offload_ctx(tls_ctx);
	struct tls_record_info *record = ctx->open_record;
	struct page_frag *pfrag;
	int copy, rc = 0;
	size_t orig_size = size;
	u32 max_open_record_len;
	long timeo;
	int more = flags & (MSG_SENDPAGE_NOTLAST | MSG_MORE);
	int tls_push_record_flags = flags | MSG_SENDPAGE_NOTLAST;
	bool last = false;

	if (sk->sk_err)
		return sk->sk_err;

	/* Only one writer at a time is allowed */
	if (sk->sk_write_pending)
		return -EBUSY;
	timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);
	pfrag = sk_page_frag(sk);

	/* KTLS_TLS_HEADER_SIZE is not counted as part of the TLS record, and
	 * we need to leave room for an authentication tag.
	 */
	max_open_record_len = TLS_MAX_PAYLOAD_SIZE
			+ TLS_HEADER_SIZE - tls_ctx->tag_size;

	if (tls_is_pending_open_record(tls_ctx)) {
		rc = tls_push_paritial_record(sk, tls_ctx, flags);
		if (rc < 0)
			return rc;
	}

	do {
		if (tls_do_allocation(sk, ctx, pfrag,
				      tls_ctx->prepand_size)) {
			rc = sk_stream_wait_memory(sk, &timeo);
			if (!rc)
				continue;

			record = ctx->open_record;
			if (!record)
				break;
handle_error:
			if (record_type != TLS_RECORD_TYPE_DATA) {
				/* avoid sending partial
				 * record with type !=
				 * application_data
				 */
				size = orig_size;
				destroy_record(record);
				ctx->open_record = NULL;
			} else if (record->len > tls_ctx->prepand_size) {
				goto last_record;
			}

			break;
		}

		record = ctx->open_record;
		copy = min_t(size_t, size, (pfrag->size - pfrag->offset));
		copy = min_t(size_t, copy, (max_open_record_len - record->len));

		if (copy_from_iter_nocache(
				page_address(pfrag->page) + pfrag->offset,
				copy, msg_iter) != copy) {
			rc = -EFAULT;
			goto handle_error;
		}
		tls_append_frag(record, pfrag, copy);

		size -= copy;
		if (!size) {
last_record:
			tls_push_record_flags = flags;
			last = true;
		}

		if ((last && !more) ||
		    (record->len >= max_open_record_len) ||
		    (record->num_frags >= MAX_SKB_FRAGS - 1)) {
			rc = tls_push_record(sk,
					     tls_ctx,
					     ctx,
					     record,
					     pfrag,
					     tls_push_record_flags,
					     record_type);
			if (rc < 0)
				break;
		}
	} while (!last);

	if (orig_size - size > 0) {
		rc = orig_size - size;
		if (record_type != TLS_RECORD_TYPE_DATA)
			rc++;
	}

	return rc;
}

static inline bool record_is_open(struct sock *sk)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_offload_context *ctx = tls_offload_ctx(tls_ctx);
	struct tls_record_info *record = ctx->open_record;

	return record;
}

int tls_device_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
{
	unsigned char record_type = TLS_RECORD_TYPE_DATA;
	int rc = 0;

	lock_sock(sk);

	if (unlikely(msg->msg_flags & MSG_OOB)) {
		if ((msg->msg_flags & MSG_MORE) || record_is_open(sk)) {
			rc = -EINVAL;
			goto out;
		}

		if (copy_from_iter(&record_type, 1, &msg->msg_iter) != 1) {
			rc = -EFAULT;
			goto out;
		}

		--size;
		msg->msg_flags &= ~MSG_OOB;
	}

	rc = tls_push_data(sk, &msg->msg_iter, size,
			   msg->msg_flags,
			   record_type);

out:
	release_sock(sk);
	return rc;
}

int tls_device_sendpage(struct sock *sk, struct page *page,
			int offset, size_t size, int flags)
{
	struct iov_iter	msg_iter;
	struct kvec iov;
	char *kaddr = kmap(page);
	int rc = 0;

	if (flags & MSG_SENDPAGE_NOTLAST)
		flags |= MSG_MORE;

	lock_sock(sk);

	if (flags & MSG_OOB) {
		rc = -ENOTSUPP;
		goto out;
	}

	iov.iov_base = kaddr + offset;
	iov.iov_len = size;
	iov_iter_kvec(&msg_iter, WRITE | ITER_KVEC, &iov, 1, size);
	rc = tls_push_data(sk, &msg_iter, size,
			   flags,
			   TLS_RECORD_TYPE_DATA);
	kunmap(page);

out:
	release_sock(sk);
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

	if (ctx->priv_ctx) {
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

	ctx->prepand_size = TLS_HEADER_SIZE + nonece_size;
	ctx->tag_size = tag_size;
	ctx->iv_size = iv_size;
	ctx->iv = kmalloc(iv_size, GFP_KERNEL);
	if (!ctx->iv) {
		rc = -ENOMEM;
		goto detach_sock;
	}
	memcpy(ctx->iv, iv, iv_size);

	offload_ctx = ctx->priv_ctx;
	dummy_record->end_seq = offload_ctx->expectedSN;
	dummy_record->len = 0;
	dummy_record->num_frags = 0;

	INIT_LIST_HEAD(&offload_ctx->records_list);
	list_add_tail(&dummy_record->list, &offload_ctx->records_list);
	spin_lock_init(&offload_ctx->lock);

	inet_csk(sk)->icsk_clean_acked = &tls_icsk_clean_acked;

	/* After this line the tx_handler might access the offload context */
	smp_store_release(&sk->sk_destruct,
			  &tls_device_sk_destruct);
	goto out;

detach_sock:
	detach_sock_from_netdev(sk, ctx);
err_dummy_record:
	kfree(dummy_record);
out:
	return rc;
}
