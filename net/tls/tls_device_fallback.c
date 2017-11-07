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

#include <net/tls.h>
#include <crypto/aead.h>
#include <crypto/scatterwalk.h>

static void chain_to_walk(struct scatterlist *sg, struct scatter_walk *walk)
{
	struct scatterlist *src = walk->sg;
	int diff = walk->offset - src->offset;

	sg_set_page(sg, sg_page(src),
		    src->length - diff, walk->offset);

	scatterwalk_crypto_chain(sg, sg_next(src), 0, 2);
}

static int tls_enc_record(struct aead_request *aead_req,
			  struct crypto_aead *aead, char *aad, char *iv,
			  __be64 rcd_sn, struct scatter_walk *in,
			  struct scatter_walk *out, int *in_len)
{
	struct scatterlist sg_in[3];
	struct scatterlist sg_out[3];
	unsigned char buf[TLS_HEADER_SIZE + TLS_CIPHER_AES_GCM_128_IV_SIZE];
	u16 len;
	int rc;

	len = min_t(int, *in_len, ARRAY_SIZE(buf));

	scatterwalk_copychunks(buf, in, len, 0);
	scatterwalk_copychunks(buf, out, len, 1);

	*in_len -= len;
	if (!*in_len)
		return 0;

	scatterwalk_pagedone(in, 0, 1);
	scatterwalk_pagedone(out, 1, 1);

	len = buf[4] | (buf[3] << 8);
	len -= TLS_CIPHER_AES_GCM_128_IV_SIZE;

	tls_make_aad(aad, len - TLS_CIPHER_AES_GCM_128_TAG_SIZE,
		     (char *)&rcd_sn, sizeof(rcd_sn), buf[0]);

	memcpy(iv + TLS_CIPHER_AES_GCM_128_SALT_SIZE, buf + TLS_HEADER_SIZE,
	       TLS_CIPHER_AES_GCM_128_IV_SIZE);

	sg_init_table(sg_in, ARRAY_SIZE(sg_in));
	sg_init_table(sg_out, ARRAY_SIZE(sg_out));
	sg_set_buf(sg_in, aad, TLS_AAD_SPACE_SIZE);
	sg_set_buf(sg_out, aad, TLS_AAD_SPACE_SIZE);
	chain_to_walk(sg_in + 1, in);
	chain_to_walk(sg_out + 1, out);

	*in_len -= len;
	if (*in_len < 0) {
		*in_len += TLS_CIPHER_AES_GCM_128_TAG_SIZE;
		if (*in_len < 0)
		/* the input buffer doesn't contain the entire record.
		 * trim len accordingly. The resulting authentication tag
		 * will contain garbage. but we don't care as we won't
		 * include any of it in the output skb
		 * Note that we assume the output buffer length
		 * is larger then input buffer length + tag size
		 */
			len += *in_len;

		*in_len = 0;
	}

	if (*in_len) {
		scatterwalk_copychunks(NULL, in, len, 2);
		scatterwalk_pagedone(in, 0, 1);
		scatterwalk_copychunks(NULL, out, len, 2);
		scatterwalk_pagedone(out, 1, 1);
	}

	len -= TLS_CIPHER_AES_GCM_128_TAG_SIZE;
	aead_request_set_crypt(aead_req, sg_in, sg_out, len, iv);

	rc = crypto_aead_encrypt(aead_req);

	return rc;
}

static void tls_init_aead_request(struct aead_request *aead_req,
				  struct crypto_aead *aead)
{
	aead_request_set_tfm(aead_req, aead);
	aead_request_set_ad(aead_req, TLS_AAD_SPACE_SIZE);
	/* Clear the CRYPTO_TFM_REQ_MAY_SLEEP flag to avoid
	 * "sleeping function called from invalid context " warning
	 */
	//aead_request_set_callback(aead_req, 0, NULL, NULL);
}

static struct aead_request *tls_alloc_aead_request(struct crypto_aead *aead,
						   gfp_t flags)
{
	unsigned int req_size = sizeof(struct aead_request) +
		crypto_aead_reqsize(aead);

	struct aead_request* aead_req;

	aead_req = kzalloc(req_size, flags);
	if (!aead)
		return NULL;

	tls_init_aead_request(aead_req, aead);
	return aead_req;
}

static int tls_enc_records(struct aead_request *aead_req,
			   struct crypto_aead *aead, struct scatterlist *sg_in,
			   struct scatterlist *sg_out, char *aad, char *iv,
			   u64 rcd_sn, int len)
{
	struct scatter_walk in;
	struct scatter_walk out;
	int rc;

	scatterwalk_start(&in, sg_in);
	scatterwalk_start(&out, sg_out);

	do {
		rc = tls_enc_record(aead_req, aead, aad, iv,
				    cpu_to_be64(rcd_sn), &in, &out, &len);
		rcd_sn++;

	} while (rc == 0 && len);

	scatterwalk_done(&in, 0, 0);
	scatterwalk_done(&out, 1, 0);

	return rc;
}

static void complete_skb(struct sk_buff *nskb, struct sk_buff *skb, int headln)
{
	skb_copy_header(nskb, skb);

	skb_put(nskb, skb->len);
	memcpy(nskb->data, skb->data, headln);

	/* All TLS offload devices support CHECKSUM_PARTIAL
	 * and since the pseudo header didn't change
	 * we don't have to update the checksum
	 */
	BUG_ON(skb->ip_summed != CHECKSUM_PARTIAL);

	nskb->destructor = skb->destructor;
	nskb->sk = skb->sk;
	skb->destructor = NULL;
	skb->sk = NULL;
	refcount_add(nskb->truesize - skb->truesize,
		     &nskb->sk->sk_wmem_alloc);
}
/* This function may be called after the user socket is already
 * closed so make sure we don't use anything freed during
 * tls_sk_proto_close here
 */
struct sk_buff *tls_sw_fallback(struct sock *sk, struct sk_buff *skb)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_offload_context *ctx = tls_offload_ctx(tls_ctx);
	struct tls_record_info *record;
	u32 tcp_seq = ntohl(tcp_hdr(skb)->seq);
	s32 sync_size;
	int remaining;
	unsigned long flags;
	struct sk_buff *nskb = NULL;
	int i = 0;
	struct scatterlist sg_in[2 * (MAX_SKB_FRAGS + 1)];
	struct scatterlist sg_out[3];
	struct aead_request *aead_req;
	int tcp_header_size = tcp_hdrlen(skb);
	int tcp_payload_offset = skb_transport_offset(skb) + tcp_header_size;
	void *buf, *dummy_buf, *iv, *aad;
	int buf_len;
	int resync_sgs;
	int rc;
	int payload_len = skb->len - tcp_payload_offset;
	u64 rcd_sn;

	if (!payload_len)
		return skb;

	sg_init_table(sg_in, ARRAY_SIZE(sg_in));
	sg_init_table(sg_out, ARRAY_SIZE(sg_out));

	spin_lock_irqsave(&ctx->lock, flags);
	record = tls_get_record(ctx, tcp_seq, &rcd_sn);
	if (!record) {
		spin_unlock_irqrestore(&ctx->lock, flags);
		WARN(1, "Record not found for seq %u\n", tcp_seq);
		goto free_orig;
	}

	sync_size = tcp_seq - (record->end_seq - record->len);
	if (sync_size < 0) {
		spin_unlock_irqrestore(&ctx->lock, flags);
		if (!tls_record_is_start_marker(record))
		/* This should only occur if the relevant record was
		 * already acked. In that case it should be ok
		 * to drop the packet and avoid retransmission.
		 *
		 * There is a corner case where the packet contains
		 * both an acked and a non-acked record.
		 * We currently don't handle that case and rely
		 * on TCP to retranmit a packet that doesn't contain
		 * already acked payload.
		 */
			goto free_orig;

		if (payload_len > -sync_size) {
			WARN(1, "Fallback of partially offloaded packets is not supported\n");
			goto free_orig;
		} else {
			return skb;
		}
	}

	remaining = sync_size;
	while (remaining > 0) {
		skb_frag_t *frag = &record->frags[i];

		__skb_frag_ref(frag);
		sg_set_page(sg_in + i, skb_frag_page(frag),
			    skb_frag_size(frag), frag->page_offset);

		remaining -= skb_frag_size(frag);

		if (remaining < 0)
			sg_in[i].length += remaining;

		i++;
	}
	spin_unlock_irqrestore(&ctx->lock, flags);
	resync_sgs = i;

	aead_req = tls_alloc_aead_request(ctx->aead_send, GFP_ATOMIC);
	if (!aead_req)
		goto put_sg;

	buf_len = TLS_CIPHER_AES_GCM_128_SALT_SIZE +
		  TLS_CIPHER_AES_GCM_128_IV_SIZE +
		  TLS_AAD_SPACE_SIZE +
		  sync_size +
		  tls_ctx->tag_size;
	buf = kmalloc(buf_len, GFP_ATOMIC);
	if (!buf)
		goto free_req;

	nskb = alloc_skb(skb_headroom(skb) + skb->len, GFP_ATOMIC);
	if (!nskb)
		goto free_req;

	skb_reserve(nskb, skb_headroom(skb));

	iv = buf;

	memcpy(iv, tls_ctx->crypto_send_aes_gcm_128.salt,
	       TLS_CIPHER_AES_GCM_128_SALT_SIZE);
	aad = buf + TLS_CIPHER_AES_GCM_128_SALT_SIZE +
	      TLS_CIPHER_AES_GCM_128_IV_SIZE;
	dummy_buf = aad + TLS_AAD_SPACE_SIZE;

	sg_set_buf(&sg_out[0], dummy_buf, sync_size);
	sg_set_buf(&sg_out[1], nskb->data + tcp_payload_offset,
		   payload_len);
	/* Add room for authentication tag produced by crypto */
	dummy_buf += sync_size;
	sg_set_buf(&sg_out[2], dummy_buf, tls_ctx->tag_size);
	rc = skb_to_sgvec(skb, &sg_in[i], tcp_payload_offset,
			  payload_len);
	if (rc < 0)
		goto free_nskb;

	rc = tls_enc_records(aead_req, ctx->aead_send, sg_in, sg_out, aad, iv,
			     rcd_sn, sync_size + payload_len);
	if (rc < 0)
		goto free_nskb;

	complete_skb(nskb, skb, tcp_payload_offset);

free_buf:
	kfree(buf);
free_req:
	kfree(aead_req);
put_sg:
	for (i = 0; i < resync_sgs; i++)
		put_page(sg_page(&sg_in[i]));
free_orig:
	kfree_skb(skb);
	return nskb;

free_nskb:
	kfree_skb(nskb);
	nskb = NULL;
	goto free_buf;
}

static struct sk_buff *
tls_validate_xmit(struct sock *sk, struct net_device *dev, struct sk_buff *skb)
{
	if (dev == tls_get_ctx(sk)->netdev)
		return skb;

	return tls_sw_fallback(sk, skb);
}

int tls_sw_fallback_init(struct sock *sk,
			 struct tls_offload_context *offload_ctx,
			 struct tls_crypto_info *crypto_info)
{
	int rc;

	offload_ctx->aead_send = crypto_alloc_aead("gcm(aes)", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(offload_ctx->aead_send)) {
		pr_err("crypto_alloc_aead failed\n");
		rc = PTR_ERR(offload_ctx->aead_send);
		offload_ctx->aead_send = NULL;
		goto err_out;
	}

	rc = crypto_aead_setkey(
		offload_ctx->aead_send,
		((struct tls12_crypto_info_aes_gcm_128 *)crypto_info)->key,
		TLS_CIPHER_AES_GCM_128_KEY_SIZE);
	if (rc)
		goto free_aead;

	rc = crypto_aead_setauthsize(offload_ctx->aead_send,
				     TLS_CIPHER_AES_GCM_128_TAG_SIZE);
	if (rc)
		goto free_aead;

	sk->sk_offload_check = tls_validate_xmit;
	/* After the next line tls_is_sk_tx_device_offloaded
	 * will return true and ndo_start_xmit might access the
	 * offload context
	 */
	return 0;
free_aead:
	crypto_free_aead(offload_ctx->aead_send);
err_out:
	return rc;
}
