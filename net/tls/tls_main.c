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

MODULE_AUTHOR("Mellanox Technologies");
MODULE_DESCRIPTION("Transport Layer Security Support");
MODULE_LICENSE("Dual BSD/GPL");

static struct proto tls_device_prot;
static struct proto tls_sw_prot;

int tls_push_frags(struct sock *sk,
		   struct tls_context *ctx,
		   skb_frag_t *frag,
		   u16 num_frags,
		   u16 first_offset,
		   int flags)
{
	int sendpage_flags = flags | MSG_SENDPAGE_NOTLAST;
	int ret = 0;
	size_t size;
	int offset = first_offset;

	size = skb_frag_size(frag) - offset;
	offset += frag->page_offset;

	while (1) {
		if (!--num_frags)
			sendpage_flags = flags;

		 /* is sending application-limited? */
		tcp_rate_check_app_limited(sk);
retry:
		ret = do_tcp_sendpages(sk,
				       skb_frag_page(frag),
				       offset,
				       size,
				       sendpage_flags);

		if (ret != size) {
			if (ret > 0) {
				offset += ret;
				size -= ret;
				goto retry;
			}

			offset -= frag->page_offset;
			ctx->pending_offset = offset;
			ctx->pending_frags = frag;
			ctx->num_pending_frags = num_frags + 1;
			return ret;
		}

		if (!num_frags)
			break;

		frag++;
		offset = frag->page_offset;
		size = skb_frag_size(frag);
	}

	return 0;
}

int tls_push_paritial_record(struct sock *sk, struct tls_context *ctx,
			     int flags) {
	skb_frag_t *frag = ctx->pending_frags;
	u16 offset = ctx->pending_offset;
	u16 num_frags = ctx->num_pending_frags;

	ctx->num_pending_frags = 0;

	return tls_push_frags(sk, ctx, frag,
			      num_frags, offset, flags);
}

static void tls_write_space(struct sock *sk)
{
	struct tls_context *ctx = tls_get_ctx(sk);

	if (tls_is_pending_open_record(ctx)) {
		gfp_t sk_allocation = sk->sk_allocation;
		int rc;

		sk->sk_allocation = GFP_ATOMIC;
		rc = tls_push_paritial_record(sk, ctx,
					      MSG_DONTWAIT | MSG_NOSIGNAL);
		sk->sk_allocation = sk_allocation;

		if (rc < 0)
			return;
	}

	ctx->sk_write_space(sk);
}

int tls_sk_query(struct sock *sk, int optname, char __user *optval,
		 int __user *optlen)
{
	int rc = 0;
	struct tls_context *ctx = tls_get_ctx(sk);
	struct tls_crypto_info *crypto_info;
	int len;

	if (get_user(len, optlen))
		return -EFAULT;

	if (!optval || (len < sizeof(*crypto_info))) {
		rc = -EINVAL;
		goto out;
	}

	if (!ctx) {
		rc = -EBUSY;
		goto out;
	}

	/* get user crypto info */
	switch (optname) {
	case TCP_TLS_TX: {
		crypto_info = &ctx->crypto_send;
		break;
	}
	case TCP_TLS_RX:
		/* fallthru since for now we don't support */
	default: {
		rc = -ENOPROTOOPT;
		goto out;
	}
	}

	if (!TLS_CRYPTO_INFO_READY(crypto_info)) {
		rc = -EBUSY;
		goto out;
	}

	if (len == sizeof(crypto_info)) {
		rc = copy_to_user(optval, crypto_info, sizeof(*crypto_info));
		goto out;
	}

	switch (crypto_info->cipher_type) {
	case TLS_CIPHER_AES_GCM_128: {
		struct tls_crypto_info_aes_gcm_128 *crypto_info_aes_gcm_128 =
				container_of(crypto_info,
					     struct tls_crypto_info_aes_gcm_128,
					     info);

		if (len != sizeof(*crypto_info_aes_gcm_128)) {
			rc = -EINVAL;
			goto out;
		}
		lock_sock(sk);
		memcpy(crypto_info_aes_gcm_128->iv, ctx->iv,
		       TLS_CIPHER_AES_GCM_128_IV_SIZE);
		release_sock(sk);
		rc = copy_to_user(optval,
				  crypto_info_aes_gcm_128,
				  sizeof(*crypto_info_aes_gcm_128));
		break;
	}
	default:
		rc = -EINVAL;
	}

out:
	return rc;
}
EXPORT_SYMBOL(tls_sk_query);

void tls_sk_destruct(struct sock *sk, struct tls_context *ctx)
{
	ctx->sk_destruct(sk);
	kfree(ctx->iv);
	kfree(ctx);
	module_put(THIS_MODULE);
}

int tls_sk_attach(struct sock *sk, int optname, char __user *optval,
		  unsigned int optlen)
{
	int rc = 0;
	struct tls_context *ctx = tls_get_ctx(sk);
	struct tls_crypto_info *crypto_info;
	bool allocated_tls_ctx = false;
	struct proto *prot = NULL;

	if (!optval || (optlen < sizeof(*crypto_info))) {
		rc = -EINVAL;
		goto out;
	}

	/* allocate tls context */
	if (!ctx) {
		ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
		if (!ctx) {
			rc = -ENOMEM;
			goto out;
		}
		sk->sk_user_data = ctx;
		allocated_tls_ctx = true;
	}

	/* get user crypto info */
	switch (optname) {
	case TCP_TLS_TX: {
		crypto_info = &ctx->crypto_send;
		break;
	}
	case TCP_TLS_RX:
		/* fallthru since for now we don't support */
	default: {
		rc = -ENOPROTOOPT;
		goto err_sk_user_data;
	}
	}

	/* Currently we don't support set crypto info more than one time */
	if (TLS_CRYPTO_INFO_READY(crypto_info)) {
		rc = -EEXIST;
		goto err_sk_user_data;
	}

	rc = copy_from_user(crypto_info, optval, sizeof(*crypto_info));
	if (rc) {
		rc = -EFAULT;
		goto err_sk_user_data;
	}

	/* check version */
	if (crypto_info->version != TLS_1_2_VERSION) {
		rc = -ENOTSUPP;
		goto err_crypto_info;
	}

	switch (crypto_info->cipher_type) {
	case TLS_CIPHER_AES_GCM_128: {
		if (optlen != sizeof(struct tls_crypto_info_aes_gcm_128)) {
			rc = -EINVAL;
			goto err_crypto_info;
		}
		rc = copy_from_user(crypto_info,
				    optval,
				    sizeof(struct tls_crypto_info_aes_gcm_128));
		break;
	}
	default:
		rc = -EINVAL;
		goto err_crypto_info;
	}

	if (rc) {
		rc = -EFAULT;
		goto err_crypto_info;
	}

	ctx->sk_write_space = sk->sk_write_space;
	ctx->sk_destruct = sk->sk_destruct;
	ctx->sk_close = sk->sk_prot->close;
	sk->sk_write_space = tls_write_space;
	ctx->sk_stream_memory_free = sk->sk_prot->stream_memory_free;

	if (TLS_IS_STATE_HW(crypto_info)) {
		rc = tls_set_device_offload(sk, ctx);
		prot = &tls_device_prot;
		if (rc)
			goto err_crypto_info;
	} else if (TLS_IS_STATE_SW(crypto_info)) {
		rc = tls_set_sw_offload(sk, ctx);
		prot = &tls_sw_prot;
		if (rc)
			goto err_crypto_info;
	}

	if (!try_module_get(THIS_MODULE)) {
		rc = -EINVAL;
		goto err_set_device_offload;
	}

	rc = 0;

	sk->sk_prot = prot;
	goto out;

err_set_device_offload:
	tls_clear_device_offload(sk, ctx);
err_crypto_info:
	memset(crypto_info, 0, sizeof(*crypto_info));
err_sk_user_data:
	if (allocated_tls_ctx)
		kfree(ctx);
out:
	return rc;
}
EXPORT_SYMBOL(tls_sk_attach);

static int __init tls_init(void)
{
	tls_device_prot			= tcp_prot;
	tls_device_prot.sendmsg		= tls_device_sendmsg;
	tls_device_prot.sendpage	= tls_device_sendpage;

	tls_sw_prot			= tcp_prot;
	tls_sw_prot.sendmsg		= tls_sw_sendmsg;
	tls_sw_prot.sendpage            = tls_sw_sendpage;
	tls_sw_prot.stream_memory_free  = tls_sw_stream_memory_free;
	tls_sw_prot.close               = tls_sw_close;

	return 0;
}

static void __exit tls_exit(void)
{
}

module_init(tls_init);
module_exit(tls_exit);
