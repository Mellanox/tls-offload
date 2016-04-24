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

int mlx_ipsec_hw_init(void)
{
	return 0;
}

void mlx_ipsec_hw_deinit(void)
{
}

static enum auth_identifier
mlx_ipsec_get_auth_identifier(struct xfrm_state *x)
{
	unsigned int key_len = (x->aead->alg_key_len + 7) / 8 - 4;

	/* [BP]: TODO stop assuming it is AES GCM */
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

	/* [BP]: TODO stop assuming it is AES GCM */
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

int mlx_ipsec_hw_sadb_add(struct mlx_ipsec_sa_entry *sa,
			  struct mlx_ipsec_dev *dev)
{
	unsigned int key_len = (sa->x->aead->alg_key_len + 7) / 8;
	unsigned int crypto_data_len = key_len - 4; /* 4 bytes salt at end */
	struct mlx_accel_core_dma_buf *buf = NULL;
	struct sa_cmd_v4 *cmd;
	int fifo_full;
	int res = 0;
	int len, buf_len;
	unsigned long flags;

	len = sizeof(struct sa_cmd_v4) + crypto_data_len;
	buf_len = sizeof(struct mlx_accel_core_dma_buf) + len;
	buf = kzalloc(buf_len, GFP_ATOMIC);
	if (!buf) {
		res = -ENOMEM;
		goto out;
	}

	buf->data_size = len;
	cmd = (struct sa_cmd_v4 *)buf->data;
	cmd->cmd = htonl(CMD_ADD_SA);
	cmd->sw_sa_id = htonl(sa->sw_sa_id);

	/* Is this the correct mask? */
	cmd->sip = htonl(sa->x->props.saddr.a4);
	cmd->sip_mask = htonl(sa->x->sel.prefixlen_s); /* TODO: not tested */
	cmd->dip = htonl(sa->x->id.daddr.a4);
	cmd->dip_mask = htonl(sa->x->sel.prefixlen_d); /* TODO: not tested */
	cmd->ip_protocol = htons(sa->x->id.proto);
	cmd->sport = htons(sa->x->sel.sport); /* TODO: not tested */
	cmd->sport_mask = htons(sa->x->sel.sport_mask); /* TODO: not tested */
	cmd->dport = htons(sa->x->sel.dport); /* TODO: not tested */
	cmd->dport_mask = htons(sa->x->sel.dport_mask); /* TODO: not tested */
	cmd->is_tunnel = htons(sa->x->props.mode);
	cmd->direction = htonl((sa->x->xso.flags & XFRM_OFFLOAD_INBOUND) ?
			RX_DIRECTION : TX_DIRECTION);
	cmd->udp_esp_enc_type = htonl(IPSEC_OFFLOAD_UDP_ESP_ENCAP_NONE);
	cmd->sec_assoc.spi = sa->x->id.spi;
	cmd->sec_assoc.auth.identifier =
		htonl(mlx_ipsec_get_auth_identifier(sa->x));
	cmd->sec_assoc.enc.identifier =
		htonl(mlx_ipsec_get_crypto_identifier(sa->x));
	cmd->sec_assoc.enc.key_length = htonl(key_len - 4);
	cmd->sec_assoc.enc.key_offset_bytes = 0;
	cmd->sec_assoc.enc.additional_info =
		htonl(*((__be32 *)(sa->x->aead->alg_key + key_len - 4)));
	cmd->crypto_data_len = htonl(crypto_data_len);
	memcpy(cmd->crypto_data, sa->x->aead->alg_key, crypto_data_len);

	/* serialize fifo and mlx_accel_core_sendmsg */
	spin_lock_irqsave(&dev->fifo_sa_cmds_lock, flags);
	pr_debug("adding to fifo!\n");
	fifo_full = kfifo_put(&dev->fifo_sa_cmds, sa);
	spin_unlock_irqrestore(&dev->fifo_sa_cmds_lock, flags);

	if (!fifo_full) {
		pr_warn("Fifo is full!\n");
		res = -ENOMEM;
		goto err_buf;
	}

	mlx_accel_core_sendmsg(dev->conn, buf);
	/* After this point buf will be delete in mlx_accel_core */

	/* wait for sa_add response and handle the response */
	res = wait_event_killable(dev->wq, sa->status != ADD_SA_PENDING);
	if (res != 0) {
		pr_warn("add_sa returned before receiving response\n");
		goto out;
	}

	res = sa->status;
	if (sa->status != ADD_SA_SUCCESS)
		pr_warn("add_sa failed with erro %08x\n", sa->status);
	goto out;

err_buf:
	kfree(buf);
out:
	return res;
}

int mlx_ipsec_hw_sadb_del(struct mlx_ipsec_sa_entry *sa)
{
	return 0;
}

static void mlx_ipsec_handle_add_sa(struct mlx_ipsec_dev *dev,
				    struct mlx_ipsec_sa_entry *sa_entry,
				    struct fpga_reply_add_sa *add_sa_reply)
{
	sa_entry->status = ntohl(add_sa_reply->status);
	wake_up_all(&dev->wq);
}

void mlx_ipsec_hw_qp_recv_cb(void *cb_arg, struct mlx_accel_core_dma_buf *buf)
{
	struct mlx_ipsec_dev *dev = cb_arg;
	struct fpga_reply_generic *reply =
		(struct fpga_reply_generic *)buf->data;
	struct mlx_ipsec_sa_entry *sa_entry;

	pr_debug("mlx_ipsec_qp_recv_cb() opcode %08x\n", ntohl(reply->opcode));

	/* [BP]: This should never fail - consider reset if it does */
	if (!kfifo_get(&dev->fifo_sa_cmds, &sa_entry)) {
		pr_warn("sa_hw2sw_id FIFO empty on recv callback\n");
		return;
	}

	if (sa_entry->sw_sa_id != ntohl(reply->sw_sa_id)) {
		pr_warn("mismatch sw_sa_id in FIFO %d vs %d\n",
			sa_entry->sw_sa_id, reply->sw_sa_id);
	}

	switch (ntohl(reply->opcode)) {
	case EVENT_ADD_SA_RESPONSE:
		mlx_ipsec_handle_add_sa(dev, sa_entry,
					(struct fpga_reply_add_sa *)buf->data);

		break;
	default:
		pr_warn("Unknown opcode from FPGA %08x\n",
			ntohl(reply->opcode));
	}
}
