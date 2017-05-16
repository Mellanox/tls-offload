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

#ifndef _TLS_OFFLOAD_H
#define _TLS_OFFLOAD_H

#include <linux/types.h>

#include <uapi/linux/tls.h>


/* Maximum data size carried in a TLS record */
#define TLS_MAX_PAYLOAD_SIZE		((size_t)1 << 14)

#define TLS_HEADER_SIZE			5
#define TLS_NONCE_OFFSET		TLS_HEADER_SIZE

#define TLS_CRYPTO_INFO_READY(info)	((info)->cipher_type)

#define TLS_RECORD_TYPE_DATA		0x17

#define TLS_AAD_SPACE_SIZE		21
//#define TLS_AAD_SIZE			13

struct tls_sw_context {
	struct crypto_aead *aead_send;

	/* Sending context */
	char aad_space[TLS_AAD_SPACE_SIZE];

	unsigned int sg_plaintext_size;
	int sg_plaintext_num_elem;
	struct scatterlist sg_plaintext_data[MAX_SKB_FRAGS];

	unsigned int sg_encrypted_size;
	int sg_encrypted_num_elem;
	struct scatterlist sg_encrypted_data[MAX_SKB_FRAGS];

	/* AAD | sg_plaintext_data | sg_tag */
	struct scatterlist sg_aead_in[2];
	/* AAD | sg_encrypted_data (data contain overhead for hdr&iv&tag) */
	struct scatterlist sg_aead_out[2];
};

struct tls_context {
	union {
		struct tls_crypto_info crypto_send;
		struct tls12_crypto_info_aes_gcm_128 crypto_send_aes_gcm_128;
	};

	void *priv_ctx;

	u16 prepand_size;
	u16 tag_size;
	u16 overhead_size;
	u16 iv_size;
	char *iv;
	u16 rec_seq_size;
	char *rec_seq;

	struct scatterlist *partially_sent_record;
	u16 partially_sent_offset;

	/* This is the number of unpushed frags in the open record.
	 * tls_is_partially_sent_record() should be used to determine whether
	 * we already started pushing the record and it remains open
	 * due to backpressure from the TCP layer or whether
	 * it is open due to the use of MSG_MORE OR MSG_SENDPAGE_NOTLAST.
	 */
	u16 pending_open_record_frags;
	int (*tls_push_pending_open_record)(struct sock *sk, int flags);

	void (*sk_write_space)(struct sock *sk);
	void (*sk_destruct)(struct sock *sk);

	void (*sk_proto_close)(struct sock *sk, long timeout);

	int  (*setsockopt)(struct sock *sk, int level,
			   int optname, char __user *optval,
			   unsigned int optlen);
	int  (*getsockopt)(struct sock *sk, int level,
			   int optname, char __user *optval,
			   int __user *optlen);
};

int tls_sk_query(struct sock *sk, int optname, char __user *optval,
		int __user *optlen);
int tls_sk_attach(struct sock *sk, int optname, char __user *optval,
		  unsigned int optlen);


int tls_set_sw_offload(struct sock *sk, struct tls_context *ctx);
int tls_sw_sendmsg(struct sock *sk, struct msghdr *msg, size_t size);
int tls_sw_sendpage(struct sock *sk, struct page *page,
		    int offset, size_t size, int flags);
void tls_sw_close(struct sock *sk, long timeout);

void tls_sk_destruct(struct sock *sk, struct tls_context *ctx);
void tls_icsk_clean_acked(struct sock *sk);

int tls_push_sg(struct sock *sk, struct tls_context *ctx,
		struct scatterlist *sg, u16 first_offset,
		int flags);
int tls_push_paritial_sent_record(struct sock *sk, struct tls_context *ctx,
				  int flags);

static inline bool tls_is_partially_sent_record(struct tls_context *ctx)
{
	return !!ctx->partially_sent_record;
}

static inline bool tls_is_pending_open_record(struct tls_context *tls_ctx)
{
	return tls_ctx->pending_open_record_frags &&
	       !tls_is_partially_sent_record(tls_ctx);
}

static inline void tls_err_abort(struct sock *sk)
{
	xchg(&sk->sk_err, -EBADMSG);
	sk->sk_error_report(sk);
}

static inline bool tls_bigint_increment(unsigned char *seq, int len)
{
	int i;

	for (i = len - 1; i >= 0; i--) {
		++seq[i];
		if (seq[i] != 0)
			break;
	}

	return (i == -1);
}

static inline void tls_advance_record_sn(struct sock *sk,
					 struct tls_context *ctx)
{
	if (tls_bigint_increment(ctx->rec_seq, ctx->rec_seq_size))
		tls_err_abort(sk);
	tls_bigint_increment(ctx->iv, ctx->iv_size);
}

static inline void tls_fill_prepend(struct tls_context *ctx,
			     char *buf,
			     size_t plaintext_len,
			     unsigned char record_type)
{
	size_t pkt_len, iv_size = ctx->iv_size;

	pkt_len = plaintext_len + iv_size + ctx->tag_size;

	/* we cover nonce explicit here as well, so buf should be of
	 * size KTLS_DTLS_HEADER_SIZE + KTLS_DTLS_NONCE_EXPLICIT_SIZE
	 */
	buf[0] = record_type;
	buf[1] = TLS_VERSION_MINOR(ctx->crypto_send.version);
	buf[2] = TLS_VERSION_MAJOR(ctx->crypto_send.version);
	/* we can use IV for nonce explicit according to spec */
	buf[3] = pkt_len >> 8;
	buf[4] = pkt_len & 0xFF;
	memcpy(buf + TLS_NONCE_OFFSET, ctx->iv, iv_size);
}

static inline struct tls_context *tls_get_ctx(const struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	return icsk->icsk_ulp_data;
}

static inline struct tls_sw_context *tls_sw_ctx(
		const struct tls_context *tls_ctx)
{
	return (struct tls_sw_context *)tls_ctx->priv_ctx;
}

static inline struct tls_offload_context *tls_offload_ctx(
		const struct tls_context *tls_ctx)
{
	return (struct tls_offload_context *)tls_ctx->priv_ctx;
}

int tls_proccess_cmsg(struct sock *sk, struct msghdr *msg,
		      unsigned char *record_type);

#endif /* _TLS_OFFLOAD_H */
