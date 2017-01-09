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

static struct proto tls_prot;

static int tls_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
{
	struct tls_context *ctx = sk->sk_user_data;
	int rc = 0;

	lock_sock(sk);

	if (msg->msg_flags & MSG_OOB) {
		rc = -ENOTSUPP;
		goto send_end;
	}

	sk_clear_bit(SOCKWQ_ASYNC_NOSPACE, sk);

	/* currently we support only HW offload */
	if (!TLS_CRYPTO_INFO_READY(&ctx->crypto_send) ||
	    !TLS_IS_HW_OFFLOAD(&ctx->crypto_send)) {
		rc = -EBADMSG;
		goto send_end;
	}

	rc = tls_sendmsg_with_offload(sk, msg, size);

send_end:
	release_sock(sk);
	return rc < 0 ? rc : size;
}

int tls_sk_query(struct sock *sk, int optname, char __user *optval,
		 int __user *optlen)
{
	int rc = 0;
	struct tls_context *ctx = sk->sk_user_data;
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
		if (TLS_IS_HW_OFFLOAD(crypto_info)) {
			lock_sock(sk);
			memcpy(crypto_info_aes_gcm_128->iv,
			       ctx->offload_ctx->iv,
			       TLS_CIPHER_AES_GCM_128_IV_SIZE);
			release_sock(sk);
		}
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

void tls_sk_destruct(struct sock *sk)
{
	struct tls_context *ctx = sk->sk_user_data;
	struct tls_crypto_info *crypto_info;

	ctx->sk_destruct(sk);

	if (!ctx)
		goto out;

	crypto_info = &ctx->crypto_send;
	if (TLS_IS_HW_OFFLOAD(crypto_info))
		tls_clear_device_offload(sk, ctx);

	kfree(ctx);
out:
	module_put(THIS_MODULE);
}
EXPORT_SYMBOL(tls_sk_destruct);

int tls_sk_attach(struct sock *sk, int optname, char __user *optval,
		  unsigned int optlen)
{
	int rc = 0;
	struct tls_context *ctx = sk->sk_user_data;
	struct tls_crypto_info *crypto_info;
	bool allocated_tls_ctx = false;

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

	/* currently we support only HW offload */
	if (!TLS_IS_HW_OFFLOAD(crypto_info)) {
		rc = -ENOPROTOOPT;
		goto err_crypto_info;
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

	if (TLS_IS_HW_OFFLOAD(crypto_info)) {
		rc = tls_set_device_offload(sk, ctx);
		if (rc)
			goto err_crypto_info;
	}

	rc = try_module_get(THIS_MODULE);
	if (!rc)
		goto err_set_device_offload;

	ctx->sk_destruct = sk->sk_destruct;
	/* After this line tls_is_sk_attach can be called */
	smp_store_release(&sk->sk_destruct, &tls_sk_destruct);

	/* TODO: add protection */
	sk->sk_prot = &tls_prot;
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
	tls_prot = tcp_prot;
	tls_prot.sendmsg = tls_sendmsg;
	return 0;
}

static void __exit tls_exit(void)
{
}

module_init(tls_init);
module_exit(tls_exit);
