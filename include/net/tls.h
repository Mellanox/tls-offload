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
#define TLS_IS_HW_OFFLOAD(info)		\
	((info)->offload_state == TLS_OFFLOAD_STATE_HW)

#define TLS_RECORD_TYPE_DATA		0x17


struct tls_record_info {
	struct list_head list;
	u32 end_seq;
	int len;
	int num_frags;
	skb_frag_t frags[MAX_SKB_FRAGS];
};

struct tls_offload_context {
	struct list_head records_list;
	struct tls_record_info *open_record;
	struct tls_record_info *retransmit_hint;
	u32 expectedSN;
	spinlock_t lock;	/* protects records list */

	u16 prepand_size;
	u16 tag_size;
	u16 iv_size;
	char *iv;
};

struct tls_context {
	union {
		struct tls_crypto_info crypto_send;
		struct tls_crypto_info_aes_gcm_128 crypto_send_aes_gcm_128;
	};
	struct tls_offload_context *offload_ctx;
	void (*sk_destruct)(struct sock *sk);
};


int tls_sk_query(struct sock *sk, int optname, char __user *optval,
		int __user *optlen);
int tls_sk_attach(struct sock *sk, int optname, char __user *optval,
		unsigned int optlen);

void tls_clear_device_offload(struct sock *sk, struct tls_context *ctx);
int tls_set_device_offload(struct sock *sk, struct tls_context *ctx);

int tls_sendmsg_with_offload(struct sock *sk, struct msghdr *msg, size_t size);
int tls_sendpage_with_offload(struct sock *sk, struct page *page,
			      int offset, size_t size, int flags);

struct tls_record_info *tls_get_record(struct tls_offload_context *context,
				       u32 seq);

void tls_sk_destruct(struct sock *sk);
void tls_icsk_clean_acked(struct sock *sk);

static inline bool tls_is_sk_attach(struct sock *sk)
{
	/* Before this line tls_is_sk_attach can not be called */
	return smp_load_acquire(&sk->sk_destruct) == &tls_sk_destruct;
}

static inline bool tls_is_sk_tx_offloaded(struct sock *sk)
{
	return (tls_is_sk_attach(sk) &&
		/* Before this line the tx_handler can not access
		 * the offload context
		 */
		(smp_load_acquire(&inet_csk(sk)->icsk_clean_acked) ==
		 &tls_icsk_clean_acked));
}

#endif /* _TLS_OFFLOAD_H */
