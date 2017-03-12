/*
 * af_tls: TLS socket
 *
 * Copyright (C) 2016
 *
 * Original authors:
 *   Fridolin Pokorny <fridolin.pokorny@gmail.com>
 *   Nikos Mavrogiannopoulos <nmav@gnults.org>
 *   Dave Watson <davejwatson@fb.com>
 *   Lance Chao <lancerchao@fb.com>
 *
 * Based on RFC 5288, RFC 6347, RFC 5246, RFC 6655
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 */

#include <linux/module.h>
#include <net/tcp.h>
#include <net/inet_common.h>
#include <linux/highmem.h>
#include <linux/netdevice.h>
#include <crypto/aead.h>

#include <net/tls.h>

/* Async worker */
static struct workqueue_struct *tls_tx_wq;

static struct tls_sw_context *sw_ctx(const struct sock *sk)
{
	struct tls_context *ctx = sk->sk_user_data;

	return (struct tls_sw_context *)ctx->offload_ctx;
}

static inline bool tls_stream_memory_free(const struct sock *sk)
{
	return sw_ctx(sk)->unsent < TLS_MAX_PAYLOAD_SIZE;
}

static void tls_err_abort(struct sock *sk);

static void increment_seqno(unsigned char *seq, struct sock *sk)
{
	int i;

	for (i = 7; i >= 0; i--) {
		++seq[i];
		if (seq[i] != 0)
			break;
	}
	/* Check for overflow. If overflowed, connection must
	 * disconnect.  Raise an error and notify userspace.
	 */
	if (unlikely(i == -1))
		tls_err_abort(sk);
}

static void tls_err_abort(struct sock *sk)
{
	pr_debug("tls_err_abort\n");
	xchg(&sk->sk_err, EBADMSG);
	sk->sk_error_report(sk);
}

/* Called with lower socket held */
static void tls_write_space(struct sock *sk)
{
	struct tls_sw_context *ctx = sw_ctx(sk);

	queue_work(tls_tx_wq, &ctx->send_work);
}

static void tls_kernel_sendpage(struct sock *sk);

static void tls_tx_work(struct work_struct *w)
{
	struct tls_sw_context *ctx =
			container_of(w, struct tls_sw_context, send_work);
	struct sock *sk = ctx->sk;

	pr_debug("tls_tx_work %p ctx %p\n", sk, ctx);
	lock_sock(sk);

	if (!ctx->tx_stopped)
		tls_kernel_sendpage(sk);
	release_sock(sk);
}

static inline void tls_make_prepend(struct sock *sk, char *buf,
				    size_t plaintext_len)
{
	size_t pkt_len;
	struct tls_sw_context *ctx = sw_ctx(sk);

	pkt_len = plaintext_len +
			TLS_CIPHER_AES_GCM_128_IV_SIZE +
			TLS_CIPHER_AES_GCM_128_TAG_SIZE;

	/* we cover nonce explicit here as well, so buf should be of
	 * size TLS_HEADER_SIZE + TLS_NONCE_EXPLICIT_SIZE
	 */
	buf[0] = TLS_RECORD_TYPE_DATA;
	buf[1] = ctx->version[0];
	buf[2] = ctx->version[1];
	/* we can use IV for nonce explicit according to spec */
	buf[3] = pkt_len >> 8;
	buf[4] = pkt_len & 0xFF;
	memcpy(buf + TLS_NONCE_OFFSET,
	       ctx->iv_send, TLS_CIPHER_AES_GCM_128_IV_SIZE);
}

static inline void tls_make_aad(struct sock *sk,
				int recv,
				char *buf,
				size_t size,
				char *nonce_explicit)
{
	struct tls_sw_context *ctx = sw_ctx(sk);

	memcpy(buf, nonce_explicit, TLS_NONCE_SIZE);

	buf[8] = TLS_RECORD_TYPE_DATA;
	buf[9] = ctx->version[0];
	buf[10] = ctx->version[1];
	buf[11] = size >> 8;
	buf[12] = size & 0xFF;
}

static int tls_do_encryption(struct sock *sk, struct scatterlist *sgin,
			     struct scatterlist *sgout, size_t data_len,
			     struct sk_buff *skb)
{
	struct tls_sw_context *ctx = sw_ctx(sk);
	int ret;
	unsigned int req_size = sizeof(struct aead_request) +
		crypto_aead_reqsize(ctx->aead_send);
	struct aead_request *aead_req;

	pr_debug("tls_do_encryption %p\n", sk);

	aead_req = kmalloc(req_size, GFP_ATOMIC);

	if (!aead_req)
		return -ENOMEM;

	aead_request_set_tfm(aead_req, ctx->aead_send);
	aead_request_set_ad(aead_req, TLS_AAD_SPACE_SIZE);
	aead_request_set_crypt(aead_req, sgin, sgout, data_len, ctx->iv_send);

	ret = crypto_aead_encrypt(aead_req);

	kfree(aead_req);
	if (ret < 0)
		return ret;
	tls_kernel_sendpage(sk);

	return ret;
}

/* Allocates enough pages to hold the decrypted data, as well as
 * setting ctx->sg_tx_data to the pages
 */
static int tls_pre_encrypt(struct sock *sk, size_t data_len)
{
	struct tls_sw_context *ctx = sw_ctx(sk);

	int i;
	unsigned int npages;
	size_t aligned_size;
	size_t encrypt_len;
	struct scatterlist *sg;
	int ret = 0;

	encrypt_len = data_len + TLS_OVERHEAD;
	npages = encrypt_len / PAGE_SIZE;
	aligned_size = npages * PAGE_SIZE;
	if (aligned_size < encrypt_len)
		npages++;

	ctx->order_npages = order_base_2(npages);
	WARN_ON(ctx->order_npages < 0 || ctx->order_npages > 3);
	/* The first entry in sg_tx_data is AAD so skip it */
	sg_init_table(ctx->sg_tx_data, TLS_SG_DATA_SIZE);
	sg_set_buf(&ctx->sg_tx_data[0], ctx->aad_send, sizeof(ctx->aad_send));
	ctx->pages_send = alloc_pages(GFP_KERNEL | __GFP_COMP,
				      ctx->order_npages);
	if (!ctx->pages_send) {
		ret = -ENOMEM;
		return ret;
	}

	sg = ctx->sg_tx_data + 1;
	/* For the first page, leave room for prepend. It will be
	 * copied into the page later
	 */
	sg_set_page(sg, ctx->pages_send, PAGE_SIZE - TLS_PREPEND_SIZE,
		    TLS_PREPEND_SIZE);
	for (i = 1; i < npages; i++)
		sg_set_page(sg + i, ctx->pages_send + i, PAGE_SIZE, 0);
	return ret;
}

static void tls_kernel_sendpage(struct sock *sk)
{
	int ret;
	struct sk_buff *head;
	struct tls_sw_context *ctx = sw_ctx(sk);

	ret = do_tcp_sendpages(sk, ctx->pages_send, ctx->send_offset,
			       ctx->send_len + TLS_OVERHEAD - ctx->send_offset,
			       MSG_DONTWAIT);
	if (ret > 0) {
		ctx->send_offset += ret;
		if (ctx->send_offset >= ctx->send_len + TLS_OVERHEAD) {
			/* Successfully sent the whole packet, account for it.*/
			head = skb_peek(&ctx->tx_queue);
			skb_dequeue(&ctx->tx_queue);
			/* TODO: for non-zerocopy case, need to
			 * adjust wmem / forward_alloc
			 * sk->sk_forward_alloc += ctx->send_len;
			 * sk->sk_wmem_queued -= ctx->send_len;
			 */
			kfree_skb(head);
			ctx->unsent -= ctx->send_len;
			increment_seqno(ctx->iv_send, sk);
			__free_pages(ctx->pages_send, ctx->order_npages);
			ctx->pages_send = NULL;
			sk->sk_write_space(sk);
		}
	} else if (ret != -EAGAIN) {
		tls_err_abort(sk);
	}
}

static int tls_push_zerocopy(struct sock *sk, struct scatterlist *sgin,
			     int pages, int bytes)
{
	int ret;
	struct tls_sw_context *ctx = sw_ctx(sk);

	tls_make_aad(sk, 0, ctx->aad_send, bytes, ctx->iv_send);

	sg_chain(ctx->sgaad_send, 2, sgin);
	//sg_unmark_end(&sgin[pages - 1]);
	sg_chain(sgin, pages + 1, ctx->sgtag_send);
	ret = sg_nents_for_len(ctx->sgaad_send, bytes + 13 + 16);

	ret = tls_pre_encrypt(sk, bytes);
	if (ret < 0)
		goto out;

	tls_make_prepend(sk, page_address(ctx->pages_send), bytes);

	ctx->send_len = bytes;
	ctx->send_offset = 0;

	ret = tls_do_encryption(sk,
				ctx->sgaad_send,
				ctx->sg_tx_data,
				bytes, NULL);

	if (ret < 0)
		goto out;

out:
	if (ret < 0) {
		sk->sk_err = EPIPE;
		return ret;
	}

	return 0;
}

static int tls_push(struct sock *sk)
{
	struct tls_sw_context *ctx = sw_ctx(sk);
	int bytes = min_t(int, ctx->unsent, (int)TLS_MAX_PAYLOAD_SIZE);
	int nsg, ret = 0;
	struct sk_buff *head = skb_peek(&ctx->tx_queue);

	if (!head)
		return 0;

	bytes = min_t(int, bytes, head->len);

	sg_init_table(ctx->sg_tx_data2, ARRAY_SIZE(ctx->sg_tx_data2));
	nsg = skb_to_sgvec(head, &ctx->sg_tx_data2[0], 0, bytes);

	/* The length of sg into decryption must not be over
	 * ALG_MAX_PAGES. The aad takes the first sg, so the payload
	 * must be less than ALG_MAX_PAGES - 1
	 */
	if (nsg > ALG_MAX_PAGES - 1) {
		ret = -EBADMSG;
		goto out;
	}

	tls_make_aad(sk, 0, ctx->aad_send, bytes, ctx->iv_send);

	sg_chain(ctx->sgaad_send, 2, ctx->sg_tx_data2);
	sg_chain(ctx->sg_tx_data2,
		 nsg + 1,
		 ctx->sgtag_send);

	ret = tls_pre_encrypt(sk, bytes);
	if (ret < 0)
		goto out;

	tls_make_prepend(sk, page_address(ctx->pages_send), bytes);

	ctx->send_len = bytes;
	ctx->send_offset = 0;
	head->sk = sk;

	ret = tls_do_encryption(sk,
				ctx->sgaad_send,
				ctx->sg_tx_data,
				bytes, head);

	if (ret < 0)
		goto out;

out:
	if (ret < 0) {
		sk->sk_err = EPIPE;
		return ret;
	}

	return 0;
}

static int zerocopy_from_iter(struct iov_iter *from,
			      struct scatterlist *sg, int *bytes)
{
	//int len = iov_iter_count(from);
	int n = 0;

	if (bytes)
		*bytes = 0;

	//TODO pass in number of pages
	while (iov_iter_count(from) && n < MAX_SKB_FRAGS - 1) {
		struct page *pages[MAX_SKB_FRAGS];
		size_t start;
		ssize_t copied;
		int j = 0;

		if (bytes && *bytes >= TLS_MAX_PAYLOAD_SIZE)
			break;

		copied = iov_iter_get_pages(from, pages, TLS_MAX_PAYLOAD_SIZE,
					    MAX_SKB_FRAGS - n, &start);
		if (bytes)
			*bytes += copied;
		if (copied < 0)
			return -EFAULT;

		iov_iter_advance(from, copied);

		while (copied) {
			int size = min_t(int, copied, PAGE_SIZE - start);

			sg_set_page(&sg[n], pages[j], size, start);
			start = 0;
			copied -= size;
			j++;
			n++;
		}
	}
	return n;
}

int tls_sw_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
{
	struct tls_sw_context *ctx = sw_ctx(sk);
	int ret = 0;
	long timeo = sock_sndtimeo(sk, msg->msg_flags & MSG_DONTWAIT);
	bool eor = !(msg->msg_flags & MSG_MORE);
	struct sk_buff *skb = NULL;
	size_t copy, copied = 0;

	lock_sock(sk);

	while (msg_data_left(msg)) {
		bool merge = true;
		int i;
		struct page_frag *pfrag;

		if (sk->sk_err)
			goto send_end;
		if (!sk_stream_memory_free(sk))
			goto wait_for_memory;

		skb = skb_peek_tail(&ctx->tx_queue);
		// Try for zerocopy
		if (!skb && !ctx->pages_send && eor) {
			int pages;
			int err;
			// TODO can send partial pages?
			int page_count = iov_iter_npages(&msg->msg_iter,
							 ALG_MAX_PAGES);
			struct scatterlist sgin[ALG_MAX_PAGES + 1];
			int bytes;

			sg_init_table(sgin, ALG_MAX_PAGES + 1);

			if (page_count >= ALG_MAX_PAGES)
				goto reg_send;

			// TODO check pages?
			err = zerocopy_from_iter(&msg->msg_iter, &sgin[0],
						 &bytes);
			pages = err;
			ctx->unsent += bytes;
			if (err < 0)
				goto send_end;

			// Try to send msg
			tls_push_zerocopy(sk, sgin, pages, bytes);
			for (; pages > 0; pages--)
				put_page(sg_page(&sgin[pages - 1]));
			if (err < 0) {
				tls_err_abort(sk);
				goto send_end;
			}
			continue;
		}

reg_send:
		while (!skb) {
			skb = alloc_skb(0, sk->sk_allocation);
			if (skb)
				__skb_queue_tail(&ctx->tx_queue, skb);
		}

		i = skb_shinfo(skb)->nr_frags;
		pfrag = sk_page_frag(sk);

		if (!sk_page_frag_refill(sk, pfrag))
			goto wait_for_memory;

		if (!skb_can_coalesce(skb, i, pfrag->page,
				      pfrag->offset)) {
			if (i == ALG_MAX_PAGES) {
				struct sk_buff *tskb;

				tskb = alloc_skb(0, sk->sk_allocation);
				if (!tskb)
					goto wait_for_memory;

				if (skb)
					skb->next = tskb;
				else
					__skb_queue_tail(&ctx->tx_queue,
							 tskb);

				skb = tskb;
				skb->ip_summed = CHECKSUM_UNNECESSARY;
				continue;
			}
			merge = false;
		}

		copy = min_t(int, msg_data_left(msg),
			     pfrag->size - pfrag->offset);
		copy = min_t(int, copy, TLS_MAX_PAYLOAD_SIZE - ctx->unsent);

		if (!sk_wmem_schedule(sk, copy))
			goto wait_for_memory;

		ret = skb_copy_to_page_nocache(sk, &msg->msg_iter, skb,
					       pfrag->page,
					       pfrag->offset,
					       copy);
		/* if (copy_from_iter_nocache(
		 *		page_address(pfrag->page) + pfrag->offset,
		 *		copy, &msg->msg_iter) != copy) {
		 *	ret = -EFAULT;
		 *	break;
		 * }
		 */
		//ret = 0;

		if (ret)
			goto send_end;

		/* Update the skb. */
		if (merge) {
			skb_frag_size_add(&skb_shinfo(skb)->frags[i - 1], copy);
		} else {
			skb_fill_page_desc(skb, i, pfrag->page,
					   pfrag->offset, copy);
			get_page(pfrag->page);
		}

		pfrag->offset += copy;
		copied += copy;
		ctx->unsent += copy;

		if (ctx->unsent >= TLS_MAX_PAYLOAD_SIZE) {
			ret = tls_push(sk);
			if (ret)
				goto send_end;
		}

		continue;

wait_for_memory:
		ret = tls_push(sk);
		if (ret)
			goto send_end;
//push_wait:
		set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
		ret = sk_stream_wait_memory(sk, &timeo);
		if (ret)
			goto send_end;
	}

	if (eor)
		ret = tls_push(sk);

send_end:
	ret = sk_stream_error(sk, msg->msg_flags, ret);

	/* make sure we wake any epoll edge trigger waiter */
	if (unlikely(skb_queue_len(&ctx->tx_queue) == 0 && ret == -EAGAIN))
		sk->sk_write_space(sk);

	release_sock(sk);
	return ret < 0 ? ret : size;
}

void tls_sw_sk_destruct(struct sock *sk)
{
	struct tls_sw_context *ctx = sw_ctx(sk);

	ctx->tx_stopped = 1;

	/* restore callback and abandon socket */
	cancel_work_sync(&ctx->send_work);

	if (1 /* use_count == 0 */) {
		//destroy_workqueue(tls_tx_wq);
		tls_tx_wq = NULL;
	}

	ctx->rx_stopped = 1;
	sk->sk_write_space = ctx->saved_sk_write_space;

	kfree(ctx->iv_send);

	kfree(ctx->key_send.key);

	crypto_free_aead(ctx->aead_send);

	if (ctx->pages_send)
		__free_pages(ctx->pages_send, ctx->order_npages);

	skb_queue_purge(&ctx->tx_queue);
	tls_sk_destruct(sk, sk->sk_user_data);
}

int tls_set_sw_offload(struct sock *sk, struct tls_context *ctx)
{
	char keyval[TLS_CIPHER_AES_GCM_128_KEY_SIZE +
		TLS_CIPHER_AES_GCM_128_SALT_SIZE];
	struct tls_crypto_info *crypto_info;
	struct tls_crypto_info_aes_gcm_128 *gcm_128_info;
	struct tls_sw_context *offload_ctx;
	u16 nonece_size, tag_size, iv_size;
	char *iv;
	int rc = 0;

	if (!tls_tx_wq) { // TODO lock, refcount
		tls_tx_wq = create_workqueue("tls");
		if (!tls_tx_wq) {
			rc = -ENOMEM;
			goto out;
		}
	}

	if (!ctx) {
		rc = -EINVAL;
		goto out;
	}

	if (ctx->offload_ctx) {
		rc = -EEXIST;
		goto out;
	}

	offload_ctx = kzalloc(sizeof(*offload_ctx), GFP_KERNEL);
	if (!offload_ctx) {
		rc = -ENOMEM;
		goto out;
	}

	ctx->offload_ctx = (struct tls_offload_context *)offload_ctx;

	crypto_info = &ctx->crypto_send;
	switch (crypto_info->cipher_type) {
	case TLS_CIPHER_AES_GCM_128: {
		nonece_size = TLS_CIPHER_AES_GCM_128_IV_SIZE;
		tag_size = TLS_CIPHER_AES_GCM_128_TAG_SIZE;
		iv_size = TLS_CIPHER_AES_GCM_128_IV_SIZE;
		iv = ((struct tls_crypto_info_aes_gcm_128 *)crypto_info)->iv;
		gcm_128_info =
			(struct tls_crypto_info_aes_gcm_128 *)crypto_info;
		break;
	}
	default:
		rc = -EINVAL;
		goto out;
	}

	offload_ctx->prepend_size = TLS_HEADER_SIZE + nonece_size;
	offload_ctx->tag_size = tag_size;
	offload_ctx->iv_size = iv_size;
	offload_ctx->iv = kmalloc(iv_size, GFP_KERNEL);
	if (!offload_ctx->iv) {
		rc = ENOMEM;
		goto out;
	}
	memcpy(offload_ctx->iv, iv, iv_size);

	offload_ctx->iv_send = offload_ctx->iv;
	memset(&offload_ctx->key_send, 0, sizeof(offload_ctx->key_send));

	offload_ctx->cipher_crypto = NULL;
	memset(offload_ctx->version, 0, sizeof(offload_ctx->version));

	offload_ctx->pages_send = NULL;
	offload_ctx->unsent = 0;

	offload_ctx->attached = 0;

	/* Preallocation for sending
	 *   scatterlist: AAD | data | TAG (for crypto API)
	 *   vec: HEADER | data | TAG
	 */
	sg_init_table(offload_ctx->sg_tx_data, TLS_SG_DATA_SIZE);
	sg_set_buf(&offload_ctx->sg_tx_data[0],
		   offload_ctx->aad_send, sizeof(offload_ctx->aad_send));

	sg_set_buf(offload_ctx->sg_tx_data + TLS_SG_DATA_SIZE - 2,
		   offload_ctx->tag_send, sizeof(offload_ctx->tag_send));
	sg_mark_end(offload_ctx->sg_tx_data + TLS_SG_DATA_SIZE - 1);

	sg_init_table(offload_ctx->sgaad_send, 2);
	sg_init_table(offload_ctx->sgtag_send, 2);

	sg_set_buf(&offload_ctx->sgaad_send[0],
		   offload_ctx->aad_send, sizeof(offload_ctx->aad_send));
	/* chaining to tag is performed on actual data size when sending */
	sg_set_buf(&offload_ctx->sgtag_send[0],
		   offload_ctx->tag_send, sizeof(offload_ctx->tag_send));

	sg_unmark_end(&offload_ctx->sgaad_send[1]);
	INIT_WORK(&offload_ctx->send_work, tls_tx_work);

	offload_ctx->cipher_type = TLS_CIPHER_AES_GCM_128;
	offload_ctx->cipher_crypto = "rfc5288(gcm(aes))";
	offload_ctx->version[0] = TLS_1_2_VERSION_MAJOR;
	offload_ctx->version[1] = TLS_1_2_VERSION_MINOR;

	if (!offload_ctx->aead_send) {
		offload_ctx->aead_send =
				crypto_alloc_aead(offload_ctx->cipher_crypto,
						  CRYPTO_ALG_INTERNAL, 0);
		if (IS_ERR(offload_ctx->aead_send)) {
			rc = PTR_ERR(offload_ctx->aead_send);
			offload_ctx->aead_send = NULL;
			pr_err("bind fail\n"); // TODO
			goto out;
		}
	}

	sk->sk_write_space = tls_write_space;
	sk->sk_destruct = tls_sw_sk_destruct;

	offload_ctx->tx_stopped = 0;
	offload_ctx->attached = 1;
	skb_queue_head_init(&offload_ctx->tx_queue);
	offload_ctx->sk = sk;

	memcpy(keyval, gcm_128_info->key, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
	memcpy(keyval + TLS_CIPHER_AES_GCM_128_KEY_SIZE, gcm_128_info->salt,
	       TLS_CIPHER_AES_GCM_128_SALT_SIZE);

	rc = crypto_aead_setkey(offload_ctx->aead_send, keyval,
				TLS_CIPHER_AES_GCM_128_KEY_SIZE +
				TLS_CIPHER_AES_GCM_128_SALT_SIZE);
	if (rc)
		goto out;

	rc = crypto_aead_setauthsize(offload_ctx->aead_send, TLS_TAG_SIZE);
	if (rc)
		goto out;

out:
	return rc;
}
