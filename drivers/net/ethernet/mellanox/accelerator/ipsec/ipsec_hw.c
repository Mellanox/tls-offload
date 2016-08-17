/*
 * Copyright (c) 2015-2016 Mellanox Technologies. All rights reserved.
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

#include "ipsec_hw.h"
#include <linux/inetdevice.h>
#include <crypto/internal/geniv.h>
#include <crypto/aead.h>

static enum auth_identifier
mlx_ipsec_get_auth_identifier(struct xfrm_state *x)
{
	unsigned int key_len = (x->aead->alg_key_len + 7) / 8 - 4;

	switch (key_len) {
	case 16:
		return IPSEC_OFFLOAD_AUTH_AES_GCM_128;
	case 32:
		return IPSEC_OFFLOAD_AUTH_AES_GCM_256;
	default:
		pr_warn("Bad key len: %d for alg %s\n", key_len,
			x->aead->alg_name);
		return -1;
	}
}

static enum crypto_identifier
mlx_ipsec_get_crypto_identifier(struct xfrm_state *x)
{
	unsigned int key_len = (x->aead->alg_key_len + 7) / 8 - 4;

	switch (key_len) {
	case 16:
		return IPSEC_OFFLOAD_CRYPTO_AES_GCM_128;
	case 32:
		return IPSEC_OFFLOAD_CRYPTO_AES_GCM_256;
	default:
		pr_warn("Bad key len: %d for alg %s\n", key_len,
			x->aead->alg_name);
		return -1;
	}
}

static void mlx_ipsec_build_hw_entry(struct mlx_ipsec_sa_entry *sa,
				     struct sadb_entry *hw_entry)
{
	unsigned int crypto_data_len = (sa->x->aead->alg_key_len + 7) / 8;
	unsigned int key_len = crypto_data_len - 4; /* 4 bytes salt at end */
	struct crypto_aead *aead = sa->x->data;
	struct aead_geniv_ctx *geniv_ctx = crypto_aead_ctx(aead);
	int ivsize = crypto_aead_ivsize(aead);

	memset(hw_entry, 0, sizeof(*hw_entry));
	memcpy(&hw_entry->key, sa->x->aead->alg_key, key_len);
	/* Duplicate 128 bit key twice according to HW layout */
	if (key_len == 16)
		memcpy(&hw_entry->key[16], sa->x->aead->alg_key, key_len);
	memcpy(&hw_entry->salt_iv, geniv_ctx->salt, ivsize);
	hw_entry->enable |= SADB_SA_VALID | SADB_SPI_EN;
	hw_entry->sip = sa->x->props.saddr.a4;
	hw_entry->sip_mask = inet_make_mask(sa->x->sel.prefixlen_s);
	hw_entry->dip = sa->x->id.daddr.a4;
	hw_entry->dip_mask = inet_make_mask(sa->x->sel.prefixlen_d);
	hw_entry->spi = sa->x->id.spi;
	hw_entry->salt = *((__be32 *)(sa->x->aead->alg_key + key_len));
	hw_entry->sw_sa_handle = htonl(sa->sw_sa_id);
	hw_entry->sport = htons(sa->x->sel.sport);
	hw_entry->enable |= sa->x->sel.sport_mask ? SADB_SPORT_EN : 0;
	hw_entry->dport = htons(sa->x->sel.dport);
	hw_entry->enable |= sa->x->sel.dport_mask ? SADB_DPORT_EN : 0;
	hw_entry->ip_proto = sa->x->id.proto;
	if (hw_entry->ip_proto)
		hw_entry->enable |= SADB_IP_PROTO_EN;
	hw_entry->enc_auth_mode = mlx_ipsec_get_auth_identifier(sa->x) << 4;
	hw_entry->enc_auth_mode |= mlx_ipsec_get_crypto_identifier(sa->x);
	if (!(sa->x->xso.flags & XFRM_OFFLOAD_INBOUND))
		hw_entry->enable |= SADB_DIR_SX;
	if (sa->x->props.mode)
		hw_entry->enable |= SADB_TUNNEL | SADB_TUNNEL_EN;
}

#ifndef MLX_IPSEC_SADB_RDMA

static u64 mlx_ipsec_sadb_addr(struct mlx_ipsec_sa_entry *sa)
{
	unsigned long sa_index;

	sa_index = (ntohl(sa->x->id.daddr.a4) ^ ntohl(sa->x->id.spi)) & 0xFFFFF;
	pr_debug("sa DIP %08x SPI %08x -> Index %lu\n",
		 sa->x->id.daddr.a4, sa->x->id.spi, sa_index);
	return mlx_accel_core_ddr_base_get(sa->dev->accel_device) +
	       (sa_index * SADB_SLOT_SIZE);
}

static void mlx_ipsec_flush_cache(struct mlx_ipsec_dev *dev)
{
	int res;
	u32 dw;

	res = mlx_accel_core_mem_read(dev->accel_device, 4,
				      IPSEC_FLUSH_CACHE_ADDR, &dw,
				      MLX_ACCEL_ACCESS_TYPE_DONTCARE);
	if (res != 4) {
		pr_warn("IPSec cache flush failed on read\n");
		return;
	}

	dw ^= IPSEC_FLUSH_CACHE_BIT;
	res = mlx_accel_core_mem_write(dev->accel_device, 4,
				       IPSEC_FLUSH_CACHE_ADDR, &dw,
				       MLX_ACCEL_ACCESS_TYPE_DONTCARE);
	if (res != 4) {
		pr_warn("IPSec cache flush failed on write\n");
		return;
	}
}

int mlx_ipsec_hw_sadb_add(struct mlx_ipsec_sa_entry *sa)
{
	struct sadb_entry hw_entry;
	u64 sa_addr = mlx_ipsec_sadb_addr(sa);
	int res;

	pr_debug("sa Address %llx\n", sa_addr);

	mlx_ipsec_build_hw_entry(sa, &hw_entry);

	res = mlx_accel_core_mem_write(sa->dev->accel_device, sizeof(hw_entry),
				       sa_addr, &hw_entry,
				       MLX_ACCEL_ACCESS_TYPE_DONTCARE);
	if (res != sizeof(hw_entry)) {
		pr_warn("Writing SA to HW memory failed %d\n", res);
		goto out;
	}
	res = 0;
	mlx_ipsec_flush_cache(sa->dev);

out:
	return res;
}

void mlx_ipsec_hw_sadb_del(struct mlx_ipsec_sa_entry *sa)
{
	struct sadb_entry hw_entry;
	u64 sa_addr;
	int res;

	if (sa->dev) {
		sa_addr = mlx_ipsec_sadb_addr(sa);
		pr_debug("del_sa Address %llx\n", sa_addr);

		memset(&hw_entry, 0, sizeof(hw_entry));

		res = mlx_accel_core_mem_write(sa->dev->accel_device,
					       sizeof(hw_entry), sa_addr,
					       &hw_entry,
					       MLX_ACCEL_ACCESS_TYPE_DONTCARE);
		if (res != sizeof(hw_entry))
			pr_warn("Deleting SA in HW memory failed %d\n", res);
		mlx_ipsec_flush_cache(sa->dev);
	}
}

void mlx_ipsec_hw_qp_recv_cb(void *cb_arg, struct mlx_accel_core_dma_buf *buf)
{
	WARN_ON(buf);
}

#else /* MLX_IPSEC_SADB_RDMA */

int mlx_ipsec_hw_sadb_add(struct mlx_ipsec_sa_entry *sa)
{
	struct mlx_accel_core_dma_buf *buf = NULL;
	struct sa_cmd_v4 *cmd;
	int res = 0;
	unsigned long flags;

	buf = kzalloc(sizeof(*buf) + sizeof(*cmd), GFP_ATOMIC);
	if (!buf) {
		res = -ENOMEM;
		goto out;
	}

	buf->data_size = sizeof(*cmd);
	buf->data = buf + 1;
	cmd = buf->data;
	cmd->cmd = htonl(IPSEC_CMD_ADD_SA);

	mlx_ipsec_build_hw_entry(sa, &cmd->entry);

	/* serialize fifo and mlx_accel_core_sendmsg */
	spin_lock_irqsave(&sa->dev->fifo_sa_cmds_lock, flags);
	pr_debug("adding to fifo!\n");
	res = kfifo_put(&sa->dev->fifo_sa_cmds, sa);
	spin_unlock_irqrestore(&sa->dev->fifo_sa_cmds_lock, flags);

	if (!res) {
		dev_warn(&sa->dev->netdev->dev, "IPSec command FIFO is full\n");
		goto err_buf;
	}

	mlx_accel_core_sendmsg(sa->dev->conn, buf);
	/* After this point buf will be freed in mlx_accel_core */

	res = wait_event_killable(sa->dev->wq, sa->status != IPSEC_SA_PENDING);
	if (res != 0) {
		pr_warn("add_sa returned before receiving response\n");
		goto out;
	}

	res = sa->status;
	if (sa->status != IPSEC_RESPONSE_SUCCESS)
		pr_warn("add_sa failed with erro %08x\n", sa->status);
	goto out;

err_buf:
	kfree(buf);
out:
	return res;
}

void mlx_ipsec_hw_sadb_del(struct mlx_ipsec_sa_entry *sa)
{
	/* TODO: send DEL_SA message */
}

static void mlx_ipsec_handle_add_sa(struct mlx_ipsec_dev *dev,
				    struct mlx_ipsec_sa_entry *sa_entry,
				    struct ipsec_hw_response *resp)
{
	if (ntohl(resp->syndrome) != IPSEC_RESPONSE_SUCCESS) {
		pr_warn("Error syndrome from FPGA: %u\n",
			ntohl(resp->syndrome));
	}
	sa_entry->status = ntohl(resp->syndrome);
	wake_up_all(&dev->wq);
}

void mlx_ipsec_hw_qp_recv_cb(void *cb_arg, struct mlx_accel_core_dma_buf *buf)
{
	struct mlx_ipsec_dev *dev = cb_arg;
	struct ipsec_hw_response *resp = buf->data;
	struct mlx_ipsec_sa_entry *sa_entry;

	if (buf->data_size < sizeof(*resp)) {
		pr_warn("Short receive from FPGA IPSec: %zu < %lu bytes\n",
			buf->data_size, sizeof(*resp));
		return;
	}

	pr_debug("mlx_ipsec recv_cb syndrome %08x\n", ntohl(resp->syndrome));

	/* [BP]: This should never fail - consider reset if it does */
	if (!kfifo_get(&dev->fifo_sa_cmds, &sa_entry)) {
		pr_warn("sa_hw2sw_id FIFO empty on recv callback\n");
		return;
	}

	if (sa_entry->sw_sa_id != ntohl(resp->sw_sa_handle)) {
		pr_warn("mismatch sw_sa_id in FIFO %d vs %d\n",
			sa_entry->sw_sa_id, resp->sw_sa_handle);
	}

	mlx_ipsec_handle_add_sa(dev, sa_entry, resp);
}

#endif /* MLX_IPSEC_SADB_RDMA */
