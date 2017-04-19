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

static int tls_kernel_sendpage(struct sock *sk, int flags);

static inline void tls_make_aad(struct sock *sk,
				int recv,
				char *buf,
				size_t size,
				char *nonce_explicit,
				unsigned char record_type)
{
	memcpy(buf, nonce_explicit, TLS_NONCE_SIZE);

	buf[8] = record_type;
	buf[9] = TLS_1_2_VERSION_MAJOR;
	buf[10] = TLS_1_2_VERSION_MINOR;
	buf[11] = size >> 8;
	buf[12] = size & 0xFF;
}

static int tls_do_encryption(struct sock *sk, struct scatterlist *sgin,
			     struct scatterlist *sgout, size_t data_len,
			struct sk_buff *skb, int flags)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context *ctx = tls_sw_ctx(tls_ctx);
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
	aead_request_set_crypt(aead_req, sgin, sgout, data_len, tls_ctx->iv);

	ret = crypto_aead_encrypt(aead_req);

	kfree(aead_req);
	if (ret < 0)
		return ret;
	/* Only pass through MSG_DONTWAIT flag */
	ret = tls_kernel_sendpage(sk, flags & MSG_DONTWAIT);

	return ret;
}

/* Allocates enough pages to hold the decrypted data, as well as
 * setting ctx->sg_tx_data to the pages
 */
static int tls_pre_encrypt(struct sock *sk, size_t data_len)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context *ctx = tls_sw_ctx(tls_ctx);
	int i;
	unsigned int npages;
	size_t aligned_size;
	size_t encrypt_len;
	struct scatterlist *sg;
	int ret = 0;
	struct page *tx_pages;

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
	tx_pages = alloc_pages(GFP_KERNEL | __GFP_COMP,
			       ctx->order_npages);
	if (!tx_pages) {
		ret = -ENOMEM;
		return ret;
	}

	sg = ctx->sg_tx_data + 1;
	/* For the first page, leave room for prepend. It will be
	 * copied into the page later
	 */
	sg_set_page(sg, tx_pages, PAGE_SIZE - TLS_PREPEND_SIZE,
		    TLS_PREPEND_SIZE);
	for (i = 1; i < npages; i++)
		sg_set_page(sg + i, tx_pages + i, PAGE_SIZE, 0);

	__skb_frag_set_page(&ctx->tx_frag, tx_pages);

	return ret;
}

static void tls_release_tx_frag(struct sock *sk)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context *ctx = tls_sw_ctx(tls_ctx);
	struct page *tx_page = skb_frag_page(&ctx->tx_frag);

	if (!tls_is_pending_open_record(tls_ctx) && tx_page) {
		struct sk_buff *head;
		/* Successfully sent the whole packet, account for it*/

		head = skb_peek(&ctx->tx_queue);
		skb_dequeue(&ctx->tx_queue);
		sk->sk_wmem_queued -= ctx->wmem_len;
		sk_mem_uncharge(sk, ctx->wmem_len);
		ctx->wmem_len = 0;
		kfree_skb(head);
		ctx->unsent -= skb_frag_size(&ctx->tx_frag) - TLS_OVERHEAD;
		tls_increment_seqno(tls_ctx->iv, sk);
		__free_pages(tx_page,
			     ctx->order_npages);
		__skb_frag_set_page(&ctx->tx_frag, NULL);
	}
	ctx->sk_write_space(sk);
}

static int tls_kernel_sendpage(struct sock *sk, int flags)
{
	int ret;
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context *ctx = tls_sw_ctx(tls_ctx);

	skb_frag_size_add(&ctx->tx_frag, TLS_OVERHEAD);
	ret = tls_push_frags(sk, tls_ctx, &ctx->tx_frag, 1, 0, flags);
	if (ret >= 0)
		tls_release_tx_frag(sk);
	else if (ret != -EAGAIN)
		tls_err_abort(sk);

	return ret;
}

static int tls_push_zerocopy(struct sock *sk, struct scatterlist *sgin,
			int pages, int bytes,
			unsigned char record_type, int flags)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context *ctx = tls_sw_ctx(tls_ctx);
	int ret;

	tls_make_aad(sk, 0, ctx->aad_send, bytes, tls_ctx->iv, record_type);

	sg_chain(ctx->sgaad_send, 2, sgin);
	sg_unmark_end(&sgin[pages - 1]);
	sg_chain(sgin, pages + 1, ctx->sgtag_send);

	ret = tls_pre_encrypt(sk, bytes);
	if (ret < 0)
		goto out;

	tls_fill_prepend(tls_ctx,
			 page_address(skb_frag_page(&ctx->tx_frag)),
			 bytes, record_type);

	skb_frag_size_set(&ctx->tx_frag, bytes);

	ret = tls_do_encryption(sk,
				ctx->sgaad_send,
				ctx->sg_tx_data,
				bytes, NULL, flags);

	if (ret < 0)
		goto out;

out:
	if (ret < 0) {
		sk->sk_err = EPIPE;
		return ret;
	}

	return 0;
}

static int tls_push(struct sock *sk, unsigned char record_type, int flags)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context *ctx = tls_sw_ctx(tls_ctx);
	int bytes = min_t(int, ctx->unsent, (int)TLS_MAX_PAYLOAD_SIZE);
	int nsg, ret = 0;
	struct sk_buff *head = skb_peek(&ctx->tx_queue);

	if (!head)
		return 0;

	bytes = min_t(int, bytes, head->len);

	sg_init_table(ctx->sg_tx_preenc, ARRAY_SIZE(ctx->sg_tx_preenc));
	nsg = skb_to_sgvec(head, &ctx->sg_tx_preenc[0], 0, bytes);

	/* The length of sg into decryption must not be over
	 * ALG_MAX_PAGES. The aad takes the first sg, so the payload
	 * must be less than ALG_MAX_PAGES - 1
	 */
	if (nsg > ALG_MAX_PAGES - 1) {
		ret = -EBADMSG;
		goto out;
	}

	tls_make_aad(sk, 0, ctx->aad_send, bytes, tls_ctx->iv, record_type);

	sg_chain(ctx->sgaad_send, 2, ctx->sg_tx_preenc);
	sg_unmark_end(&ctx->sg_tx_preenc[nsg - 1]);
	sg_chain(ctx->sg_tx_preenc,
		 nsg + 1,
		 ctx->sgtag_send);

	ret = tls_pre_encrypt(sk, bytes);
	if (ret < 0)
		goto out;

	tls_fill_prepend(tls_ctx,
			 page_address(skb_frag_page(&ctx->tx_frag)),
			 bytes, record_type);

	skb_frag_size_set(&ctx->tx_frag, bytes);
	tls_ctx->pending_offset = 0;
	head->sk = sk;

	ret = tls_do_encryption(sk,
				ctx->sgaad_send,
				ctx->sg_tx_data,
				bytes, head, flags);

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
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context *ctx = tls_sw_ctx(tls_ctx);
	int ret = 0;
	long timeo = sock_sndtimeo(sk, msg->msg_flags & MSG_DONTWAIT);
	bool eor = !(msg->msg_flags & MSG_MORE);
	struct sk_buff *skb = NULL;
	size_t copy, copied = 0;
	unsigned char record_type = TLS_RECORD_TYPE_DATA;

	lock_sock(sk);

	if (msg->msg_flags & MSG_OOB) {
		if (!eor || ctx->unsent) {
			ret = -EINVAL;
			goto send_end;
		}

		ret = copy_from_iter(&record_type, 1, &msg->msg_iter);
		if (ret != 1) {
			return -EFAULT;
			goto send_end;
		}
	}

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
		if (!skb && !skb_frag_page(&ctx->tx_frag) && eor) {
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
			tls_push_zerocopy(sk, sgin, pages, bytes,
					  record_type, msg->msg_flags);
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
		ctx->wmem_len += copy;
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
			ret = tls_push(sk, record_type, msg->msg_flags);
			if (ret)
				goto send_end;
		}

		continue;

wait_for_memory:
		ret = tls_push(sk, record_type);
		if (ret)
			goto send_end;
//push_wait:
		set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
		ret = sk_stream_wait_memory(sk, &timeo);
		if (ret)
			goto send_end;
	}

	if (eor)
		ret = tls_push(sk, record_type, msg->msg_flags);

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
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context *ctx = tls_sw_ctx(tls_ctx);
	struct page *tx_page = skb_frag_page(&ctx->tx_frag);

	crypto_free_aead(ctx->aead_send);

	if (tx_page)
		__free_pages(tx_page, ctx->order_npages);

	skb_queue_purge(&ctx->tx_queue);
	tls_sk_destruct(sk, tls_ctx);
}

int tls_set_sw_offload(struct sock *sk, struct tls_context *ctx)
{
	char keyval[TLS_CIPHER_AES_GCM_128_KEY_SIZE +
		TLS_CIPHER_AES_GCM_128_SALT_SIZE];
	struct tls_crypto_info *crypto_info;
	struct tls_crypto_info_aes_gcm_128 *gcm_128_info;
	struct tls_sw_context *sw_ctx;
	u16 nonece_size, tag_size, iv_size;
	char *iv;
	int rc = 0;

	if (!ctx) {
		rc = -EINVAL;
		goto out;
	}

	if (ctx->priv_ctx) {
		rc = -EEXIST;
		goto out;
	}

	sw_ctx = kzalloc(sizeof(*sw_ctx), GFP_KERNEL);
	if (!sw_ctx) {
		rc = -ENOMEM;
		goto out;
	}

	ctx->priv_ctx = (struct tls_offload_context *)sw_ctx;

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

	ctx->prepand_size = TLS_HEADER_SIZE + nonece_size;
	ctx->tag_size = tag_size;
	ctx->iv_size = iv_size;
	ctx->iv = kmalloc(iv_size, GFP_KERNEL);
	if (!ctx->iv) {
		rc = ENOMEM;
		goto out;
	}
	memcpy(ctx->iv, iv, iv_size);

	/* Preallocation for sending
	 *   scatterlist: AAD | data | TAG (for crypto API)
	 *   vec: HEADER | data | TAG
	 */
	sg_init_table(sw_ctx->sg_tx_data, TLS_SG_DATA_SIZE);
	sg_set_buf(&sw_ctx->sg_tx_data[0], sw_ctx->aad_send,
		   sizeof(sw_ctx->aad_send));

	sg_set_buf(sw_ctx->sg_tx_data + TLS_SG_DATA_SIZE - 2,
		   sw_ctx->tag_send, sizeof(sw_ctx->tag_send));
	sg_mark_end(sw_ctx->sg_tx_data + TLS_SG_DATA_SIZE - 1);

	sg_init_table(sw_ctx->sgaad_send, 2);
	sg_init_table(sw_ctx->sgtag_send, 2);

	sg_set_buf(&sw_ctx->sgaad_send[0], sw_ctx->aad_send,
		   sizeof(sw_ctx->aad_send));
	/* chaining to tag is performed on actual data size when sending */
	sg_set_buf(&sw_ctx->sgtag_send[0], sw_ctx->tag_send,
		   sizeof(sw_ctx->tag_send));

	sg_unmark_end(&sw_ctx->sgaad_send[1]);

	if (!sw_ctx->aead_send) {
		sw_ctx->aead_send =
				crypto_alloc_aead("rfc5288(gcm(aes))",
						  CRYPTO_ALG_INTERNAL, 0);
		if (IS_ERR(sw_ctx->aead_send)) {
			rc = PTR_ERR(sw_ctx->aead_send);
			sw_ctx->aead_send = NULL;
			pr_err("bind fail\n"); // TODO
			goto out;
		}
	}

	sk->sk_destruct = tls_sw_sk_destruct;
	sw_ctx->sk_write_space = ctx->sk_write_space;
	ctx->sk_write_space =  tls_release_tx_frag;

	skb_queue_head_init(&sw_ctx->tx_queue);
	sw_ctx->sk = sk;

	memcpy(keyval, gcm_128_info->key, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
	memcpy(keyval + TLS_CIPHER_AES_GCM_128_KEY_SIZE, gcm_128_info->salt,
	       TLS_CIPHER_AES_GCM_128_SALT_SIZE);

	rc = crypto_aead_setkey(sw_ctx->aead_send, keyval,
				TLS_CIPHER_AES_GCM_128_KEY_SIZE +
				TLS_CIPHER_AES_GCM_128_SALT_SIZE);
	if (rc)
		goto out;

	rc = crypto_aead_setauthsize(sw_ctx->aead_send, TLS_TAG_SIZE);
	if (rc)
		goto out;

out:
	return rc;
}

int tls_sw_sendpage(struct sock *sk, struct page *page,
		    int offset, size_t size, int flags)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context *ctx = tls_sw_ctx(tls_ctx);
	int ret = 0, i;
	long timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);
	bool eor;
	struct sk_buff *skb = NULL;
	size_t queued = 0;
	unsigned char record_type = TLS_RECORD_TYPE_DATA;

	if (flags & MSG_SENDPAGE_NOTLAST)
		flags |= MSG_MORE;

	/* No MSG_EOR from splice, only look at MSG_MORE */
	eor = !(flags & MSG_MORE);

	lock_sock(sk);

	if (flags & MSG_OOB) {
		ret = -ENOTSUPP;
		goto sendpage_end;
	}
	sk_clear_bit(SOCKWQ_ASYNC_NOSPACE, sk);

	/* Call the sk_stream functions to manage the sndbuf mem. */
	while (size > 0) {
		size_t send_size = min(size, TLS_MAX_PAYLOAD_SIZE);

		if (!sk_stream_memory_free(sk) ||
		    (ctx->unsent + send_size > TLS_MAX_PAYLOAD_SIZE)) {
			ret = tls_push(sk, record_type, flags);
			if (ret)
				goto sendpage_end;
			set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
			ret = sk_stream_wait_memory(sk, &timeo);
			if (ret)
				goto sendpage_end;
		}

		if (sk->sk_err)
			goto sendpage_end;

		skb = skb_peek_tail(&ctx->tx_queue);
		if (skb) {
			i = skb_shinfo(skb)->nr_frags;

			if (skb_can_coalesce(skb, i, page, offset)) {
				skb_frag_size_add(
					&skb_shinfo(skb)->frags[i - 1],
					send_size);
				skb_shinfo(skb)->tx_flags |= SKBTX_SHARED_FRAG;
				goto coalesced;
			}

			if (i >= ALG_MAX_PAGES) {
				struct sk_buff *tskb;

				tskb = alloc_skb(0, sk->sk_allocation);
				while (!tskb) {
					ret = tls_push(sk, record_type, flags);
					if (ret)
						goto sendpage_end;
					set_bit(SOCK_NOSPACE,
						&sk->sk_socket->flags);
					ret = sk_stream_wait_memory(sk, &timeo);
					if (ret)
						goto sendpage_end;

					tskb = alloc_skb(0, sk->sk_allocation);
				}

				if (skb)
					skb->next = tskb;
				else
					__skb_queue_tail(&ctx->tx_queue,
							 tskb);
				skb = tskb;
				i = 0;
			}
		} else {
			skb = alloc_skb(0, sk->sk_allocation);
			__skb_queue_tail(&ctx->tx_queue, skb);
			i = 0;
		}

		get_page(page);
		skb_fill_page_desc(skb, i, page, offset, send_size);
		skb_shinfo(skb)->tx_flags |= SKBTX_SHARED_FRAG;

coalesced:
		skb->len += send_size;
		skb->data_len += send_size;
		skb->truesize += send_size;
		sk->sk_wmem_queued += send_size;
		ctx->wmem_len += send_size;
		sk_mem_charge(sk, send_size);
		ctx->unsent += send_size;
		queued += send_size;
		offset += queued;
		size -= send_size;

		if (eor || ctx->unsent >= TLS_MAX_PAYLOAD_SIZE) {
			ret = tls_push(sk, record_type, flags);
			if (ret)
				goto sendpage_end;
		}
	}

	if (eor || ctx->unsent >= TLS_MAX_PAYLOAD_SIZE)
		ret = tls_push(sk, record_type, flags);

sendpage_end:
	ret = sk_stream_error(sk, flags, ret);

	if (ret < 0)
		ret = sk_stream_error(sk, flags, ret);

	release_sock(sk);

	return ret < 0 ? ret : queued;
}
