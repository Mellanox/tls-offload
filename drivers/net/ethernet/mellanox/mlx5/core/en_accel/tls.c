/*
 * Copyright (c) 2017 Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
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
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#include <linux/netdevice.h>
#include "en_accel/tls.h"
#include "fpga/tls.h"

/* Start of context identifiers range (inclusive) */
#define SWID_START	5
/* End of context identifiers range (exclusive) */
#define SWID_END	BIT(24)

static int mlx_tls_add_tx_ctx(struct mlx5e_priv *priv, struct sock *sk,
			      struct tls12_crypto_info_aes_gcm_128 *crypto_info)
{
	struct mlx_tls_offload_context *context;
	int swid;
	int ret;

	swid = ida_simple_get(&priv->tls->tx_halloc, SWID_START, SWID_END,
			      GFP_KERNEL);
	if (swid < 0) {
		pr_err("mlx_tls_add(): Failed to allocate swid\n");
		ret = swid;
		goto out;
	}

	context = kzalloc(sizeof(*context), GFP_KERNEL);
	if (!context) {
		ret = -ENOMEM;
		goto release_swid;
	}

	context->swid = htonl(swid);
	context->context.expected_seq = tcp_sk(sk)->write_seq;

	ret = mlx5_fpga_tls_hw_start_tx_cmd(priv->mdev, sk, crypto_info,
					    context->context.expected_seq,
					    swid);
	if (ret)
		goto relese_context;

	tls_get_ctx(sk)->priv_ctx = &context->context;

	return ret;

relese_context:
	kfree(context);
release_swid:
	ida_simple_remove(&priv->tls->tx_halloc, swid);
out:
	return ret;
}

static int mlx_tls_add(struct net_device *netdev, struct sock *sk,
		       enum tls_offload_ctx_dir direction,
		       struct tls_crypto_info *crypto_info)
{
	struct tls12_crypto_info_aes_gcm_128 *crypto_info_aes_gcm_128;
	struct mlx5e_priv *priv = netdev_priv(netdev);
	int ret = -EINVAL;

	netdev_dbg(netdev, "%s called with direction=%d\n",
		   __func__, direction);

	if (!crypto_info ||
	    crypto_info->cipher_type != TLS_CIPHER_AES_GCM_128) {
		netdev_err(netdev, "%s: support only aes_gcm_128\n", __func__);
		goto out;
	}
	crypto_info_aes_gcm_128 =
			(struct tls12_crypto_info_aes_gcm_128 *)crypto_info;

	if (direction == TLS_OFFLOAD_CTX_DIR_TX)
		return mlx_tls_add_tx_ctx(priv, sk, crypto_info_aes_gcm_128);

	netdev_err(netdev, "%s: invalid direction\n", __func__);
out:
	return ret;
}

int mlx5e_tls_init(struct mlx5e_priv *priv)
{
	struct mlx5e_tls *tls = NULL;

	if (!MLX5_TLS_DEV(priv->mdev)) {
		netdev_dbg(priv->netdev, "Not a TLS offload device\n");
		return 0;
	}

	tls = kzalloc(sizeof(*tls), GFP_KERNEL);
	if (!tls)
		return -ENOMEM;

	ida_init(&tls->tx_halloc);
	priv->tls = tls;
	netdev_dbg(priv->netdev, "TLS attached to netdevice\n");
	return 0;
}

void mlx5e_tls_cleanup(struct mlx5e_priv *priv)
{
	struct mlx5e_tls *tls = priv->tls;

	if (!tls)
		return;

	ida_destroy(&tls->tx_halloc);
	kfree(tls);
	priv->tls = NULL;
}

static void mlx_tls_del(struct net_device *netdev, struct tls_context *tls_ctx,
			enum tls_offload_ctx_dir direction)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);

	if (direction == TLS_OFFLOAD_CTX_DIR_TX) {
		mlx5_fpga_tls_hw_stop_tx_cmd(priv,
					     mlx5e_get_tls_context(tls_ctx));
	}
}

static const struct tlsdev_ops mlx_tls_ops = {
	.tls_dev_add = mlx_tls_add,
	.tls_dev_del = mlx_tls_del,
};

void mlx5e_tls_build_netdev(struct mlx5e_priv *priv)
{
	struct net_device *netdev = priv->netdev;

	if (!priv->tls)
		return;

	netdev->features |= NETIF_F_HW_TLS_TX;
	netdev->hw_features |= NETIF_F_HW_TLS_TX;
	netdev->tlsdev_ops = &mlx_tls_ops;
}
