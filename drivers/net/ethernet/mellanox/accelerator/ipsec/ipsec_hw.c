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

#include <linux/inetdevice.h>
#include <crypto/internal/geniv.h>
#include <crypto/aead.h>
#include "ipsec_hw.h"

static enum sadb_encryption_mode
mlx_ipsec_get_encryption_mode(struct xfrm_state *x)
{
	unsigned int key_len = (x->aead->alg_key_len + 7) / 8 - 4;

	switch (key_len) {
	case 16:
		return SADB_MODE_AES_GCM_128_AUTH_128;
	case 32:
		return SADB_MODE_AES_GCM_256_AUTH_128;
	default:
		pr_warn("Bad key len: %d for alg %s\n", key_len,
			x->aead->alg_name);
		return -1;
	}
}

static void mlx_ipsec_build_hw_entry(struct mlx_ipsec_sa_entry *sa,
				     struct sadb_entry *hw_entry,
				     bool valid)
{
	unsigned int crypto_data_len;
	unsigned int key_len;
	struct crypto_aead *aead;
	struct aead_geniv_ctx *geniv_ctx;
	int ivsize;

	BUILD_BUG_ON((sizeof(struct sadb_entry) & 3) != 0);

	memset(hw_entry, 0, sizeof(*hw_entry));

	if (valid) {
		crypto_data_len = (sa->x->aead->alg_key_len + 7) / 8;
		key_len = crypto_data_len - 4; /* 4 bytes salt at end */
		aead = sa->x->data;
		geniv_ctx = crypto_aead_ctx(aead);
		ivsize = crypto_aead_ivsize(aead);

		memcpy(&hw_entry->key_enc, sa->x->aead->alg_key, key_len);
		/* Duplicate 128 bit key twice according to HW layout */
		if (key_len == 16)
			memcpy(&hw_entry->key_enc[16], sa->x->aead->alg_key,
			       key_len);
		memcpy(&hw_entry->gcm.salt_iv, geniv_ctx->salt, ivsize);
		hw_entry->gcm.salt = *((__be32 *)(sa->x->aead->alg_key +
						  key_len));
	}

	hw_entry->flags |= SADB_SA_VALID | SADB_SPI_EN;
	hw_entry->sip[3] = sa->x->props.saddr.a4;
	hw_entry->sip_masklen = sa->x->sel.prefixlen_s;
	hw_entry->dip[3] = sa->x->id.daddr.a4;
	hw_entry->dip_masklen = sa->x->sel.prefixlen_d;
	hw_entry->spi = sa->x->id.spi;
	hw_entry->sw_sa_handle = htonl(sa->handle);
	switch (sa->x->id.proto) {
	case IPPROTO_ESP:
		hw_entry->flags |= SADB_IP_ESP;
		break;
	case IPPROTO_AH:
		hw_entry->flags |= SADB_IP_AH;
		break;
	default:
		break;
	}
	hw_entry->enc_mode = mlx_ipsec_get_encryption_mode(sa->x);
	if (!(sa->x->xso.flags & XFRM_OFFLOAD_INBOUND))
		hw_entry->flags |= SADB_DIR_SX;
}

void mlx_ipsec_hw_send_complete(struct mlx_accel_core_conn *conn,
				struct mlx_accel_core_dma_buf *buf,
				struct ib_wc *wc)
{
	kfree(buf);
}

int mlx_ipsec_hw_sadb_wait(struct mlx_ipsec_sa_entry *sa)
{
	int res;

	res = wait_event_killable(sa->dev->wq, sa->status != IPSEC_SA_PENDING);
	if (res != 0) {
		pr_warn("Failure waiting for IPSec command response from HW\n");
		return -EINTR;
	}
	return 0;
}

static int mlx_ipsec_hw_cmd(struct mlx_ipsec_sa_entry *sa, u32 cmd_id)
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

	buf->complete = mlx_ipsec_hw_send_complete;
	buf->data_size = sizeof(*cmd);
	buf->data = buf + 1;
	cmd = buf->data;
	cmd->cmd = htonl(cmd_id);

	mlx_ipsec_build_hw_entry(sa, &cmd->entry, cmd_id == IPSEC_CMD_ADD_SA);

	/* Serialize fifo access */
	pr_debug("adding to fifo: sa %p handle 0x%08x\n", sa, sa->handle);
	spin_lock_irqsave(&sa->dev->fifo_sa_cmds_lock, flags);
	res = kfifo_put(&sa->dev->fifo_sa_cmds, sa);
	spin_unlock_irqrestore(&sa->dev->fifo_sa_cmds_lock, flags);

	if (!res) {
		dev_warn(&sa->dev->netdev->dev, "IPSec command FIFO is full\n");
		goto err_buf;
	}

	sa->status = IPSEC_SA_PENDING;
	res = mlx_accel_core_sendmsg(sa->dev->conn, buf);
	if (res) {
		pr_warn("Failure sending IPSec command: %d\n", res);
		goto err_buf;
	}
	/* After this point buf will be freed by completion */
	goto out;

err_buf:
	kfree(buf);
out:
	return res;
}

int mlx_ipsec_hw_sadb_add(struct mlx_ipsec_sa_entry *sa)
{
	int res;

	res = mlx_ipsec_hw_cmd(sa, IPSEC_CMD_ADD_SA);
	if (res)
		goto out;

	res = mlx_ipsec_hw_sadb_wait(sa);
	if (res)
		goto out;

	res = sa->status;
	if (sa->status != IPSEC_RESPONSE_SUCCESS)
		pr_warn("IPSec SADB add command failed with error %08x\n",
			sa->status);
out:
	return res;
}

int mlx_ipsec_hw_sadb_del(struct mlx_ipsec_sa_entry *sa)
{
	return mlx_ipsec_hw_cmd(sa, IPSEC_CMD_DEL_SA);
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

	pr_debug("mlx_ipsec recv_cb syndrome %08x sa_id %x\n",
		 ntohl(resp->syndrome), ntohl(resp->sw_sa_handle));

	/* [BP]: This should never fail - consider reset if it does */
	if (!kfifo_get(&dev->fifo_sa_cmds, &sa_entry)) {
		pr_warn("sa_hw2sw_id FIFO empty on recv callback\n");
		return;
	}
	pr_debug("Got from FIFO: sa %p handle 0x%08x\n",
		 sa_entry, sa_entry->handle);

	if (sa_entry->handle != ntohl(resp->sw_sa_handle)) {
		pr_warn("mismatch SA handle. FIFO 0x%08x vs resp 0x%08x\n",
			sa_entry->handle, ntohl(resp->sw_sa_handle));
	}

	if (ntohl(resp->syndrome) != IPSEC_RESPONSE_SUCCESS) {
		pr_warn("Error syndrome from FPGA: %u\n",
			ntohl(resp->syndrome));
	}
	sa_entry->status = ntohl(resp->syndrome);
	wake_up_all(&dev->wq);
}
