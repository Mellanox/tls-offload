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

#ifndef MLX_IPSEC_SADB_RDMA
/* [IT]: TODO get rid of this work queue:
 * Use async add/del SA operations over RDMA/RC-QP
 * Get rid of mutex lock in add/del sa flows
 * all add/del SA should work in atomic context
 */
static struct workqueue_struct *mlx_ipsec_workq;
#endif

int mlx_ipsec_hw_init(void)
{
#ifndef MLX_IPSEC_SADB_RDMA
	mlx_ipsec_workq = create_workqueue("mlx_ipsec");
	if (!mlx_ipsec_workq)
		return -ENOMEM;
#endif
	return 0;
}

void mlx_ipsec_hw_deinit(void)
{
#ifndef MLX_IPSEC_SADB_RDMA
	flush_workqueue(mlx_ipsec_workq);
	destroy_workqueue(mlx_ipsec_workq);
	mlx_ipsec_workq = NULL;
#endif
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

#ifndef MLX_IPSEC_SADB_RDMA

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

int mlx_ipsec_hw_sadb_add(struct mlx_ipsec_sa_entry *sa,
			  struct mlx_ipsec_dev *dev)
{
	unsigned int key_len = (sa->x->aead->alg_key_len + 7) / 8;
	unsigned int crypto_data_len = key_len - 4; /* 4 bytes salt at end */
	struct sadb_entry hw_entry;
	unsigned long sa_index;
	u64 sa_addr;
	int res;

	pr_debug("sa IP %08x SPI %08x\n", sa->x->id.daddr.a4, sa->x->id.spi);
	sa_index = (ntohl(sa->x->id.daddr.a4) ^ ntohl(sa->x->id.spi)) & 0xFFFFF;
	sa_addr = mlx_accel_core_ddr_base_get(dev->accel_device) +
		  (sa_index * SADB_SLOT_SIZE);
	pr_debug("sa Index %lu Address %llx\n", sa_index, sa_addr);

	memset(&hw_entry, 0, sizeof(hw_entry));
	memcpy(&hw_entry.key, sa->x->aead->alg_key, crypto_data_len);
	hw_entry.enable |= SADB_SA_VALID | SADB_SPI_EN;
	hw_entry.sip = sa->x->props.saddr.a4;
	hw_entry.sip_mask = inet_make_mask(sa->x->sel.prefixlen_s);
	hw_entry.dip = sa->x->id.daddr.a4;
	hw_entry.dip_mask = inet_make_mask(sa->x->sel.prefixlen_d);
	hw_entry.spi = sa->x->id.spi;
	hw_entry.salt = *((__be32 *)(sa->x->aead->alg_key + crypto_data_len));
	hw_entry.sw_sa_handle = htonl(sa->sw_sa_id);
	hw_entry.sport = htons(sa->x->sel.sport);
	hw_entry.enable |= sa->x->sel.sport_mask ? SADB_SPORT_EN : 0;
	hw_entry.dport = htons(sa->x->sel.dport);
	hw_entry.enable |= sa->x->sel.dport_mask ? SADB_DPORT_EN : 0;
	hw_entry.ip_proto = sa->x->id.proto;
	if (hw_entry.ip_proto)
		hw_entry.enable |= SADB_IP_PROTO_EN;
	hw_entry.enc_auth_mode = mlx_ipsec_get_auth_identifier(sa->x) << 4;
	hw_entry.enc_auth_mode |= mlx_ipsec_get_crypto_identifier(sa->x);
	if (!(sa->x->xso.flags & XFRM_OFFLOAD_INBOUND))
		hw_entry.enable |= SADB_DIR_SX;
	if (sa->x->props.mode)
		hw_entry.enable |= SADB_TUNNEL | SADB_TUNNEL_EN;

	res = mlx_accel_core_mem_write(dev->accel_device, sizeof(hw_entry),
				       sa_addr, &hw_entry,
				       MLX_ACCEL_ACCESS_TYPE_DONTCARE);
	if (res != sizeof(hw_entry)) {
		pr_warn("Writing SA to HW memory failed %d\n", res);
		goto out;
	}
	res = 0;
	mlx_ipsec_flush_cache(dev);

out:
	return res;
}

struct my_work {
	struct work_struct work;
	unsigned long sa_index;
	struct net_device *netdev;
	struct mlx_ipsec_sa_entry *sa;
	u8 xso_flags;
};

static void mlx_xfrm_del_state_work(struct work_struct *work)
{
	struct my_work *mywork = container_of(work, struct my_work, work);
	u64 sa_addr;
	struct mlx_ipsec_dev *dev;
	struct sadb_entry hw_entry;
	int res = 0;
	unsigned long flags;

	dev = mlx_ipsec_find_dev_by_netdev(mywork->netdev);
	if (dev) {
		sa_addr = mlx_accel_core_ddr_base_get(dev->accel_device) +
			  (mywork->sa_index * 4);
		pr_debug("del_sa Index %lu Address %llx\n", mywork->sa_index,
			 sa_addr);

		memset(&hw_entry, 0, sizeof(hw_entry));

		res = mlx_accel_core_mem_write(dev->accel_device,
					       sizeof(hw_entry), sa_addr,
					       &hw_entry,
					       MLX_ACCEL_ACCESS_TYPE_DONTCARE);
		if (res != sizeof(hw_entry))
			pr_warn("Deleting SA in HW memory failed %d\n", res);
		mlx_ipsec_flush_cache(dev);
	}

	if (mywork->xso_flags & XFRM_OFFLOAD_INBOUND) {
		spin_lock_irqsave(
			&dev->sw_sa_id2xfrm_state_lock,
			flags);
		hash_del_rcu(&mywork->sa->hlist);
		spin_unlock_irqrestore(
			&dev->sw_sa_id2xfrm_state_lock,
			flags);
		synchronize_rcu();
	}

	kfree(mywork->sa);
	module_put(THIS_MODULE);

	kfree(work);
}

int mlx_ipsec_hw_sadb_del(struct mlx_ipsec_sa_entry *sa)
{
	struct net_device *netdev = sa->x->xso.dev;
	unsigned long sa_index;
	struct my_work *work;
	int res = 0;

	sa_index = (sa->x->id.daddr.a4 ^ sa->x->id.spi) & 0xFFFFF;

	work = kzalloc(sizeof(*work), GFP_ATOMIC);
	if (!work) {
		res = -ENOMEM;
		goto out;
	}

	INIT_WORK(&work->work, mlx_xfrm_del_state_work);
	work->netdev = netdev;
	work->sa_index = sa_index;
	work->xso_flags = sa->x->xso.flags;
	work->sa = sa;

	queue_work(mlx_ipsec_workq, &work->work);
out:
	return res;
}

void mlx_ipsec_hw_qp_recv_cb(void *cb_arg, struct mlx_accel_core_dma_buf *buf)
{
	WARN_ON(buf);
}

#else /* MLX_IPSEC_SADB_RDMA */

int mlx_ipsec_hw_sadb_add(struct mlx_ipsec_sa_entry *sa,
			  struct mlx_ipsec_dev *dev)
{
	unsigned int key_len = (sa->x->aead->alg_key_len + 7) / 8 - 4;
	struct mlx_accel_core_dma_buf *buf = NULL;
	struct sa_cmd_v4 *cmd;
	int fifo_full;
	int res = 0;
	unsigned long flags;

	buf = kzalloc(sizeof(*buf) +
			sizeof(*cmd), GFP_ATOMIC);
	if (!buf) {
		res = -ENOMEM;
		goto out;
	}

	buf->data_size = sizeof(*cmd);
	cmd = (struct sa_cmd_v4 *)buf->data;
	cmd->cmd = htonl(CMD_ADD_SA);

	cmd->enable |= SADB_SA_VALID | SADB_SPI_EN;
	cmd->sip = htonl(sa->x->props.saddr.a4);
	cmd->sip_mask = inet_make_mask(32);
	cmd->dip = htonl(sa->x->id.daddr.a4);
	cmd->dip_mask = inet_make_mask(32);
	cmd->spi = sa->x->id.spi;
	cmd->salt = *((__be32 *)(sa->x->aead->alg_key + key_len));
	cmd->sw_sa_handle = htonl(sa->sw_sa_id);
	/* TODO: implement UDP encapsulation support to enable port selection */
	cmd->ip_proto = sa->x->id.proto;
	if (cmd->ip_proto)
		cmd->enable |= SADB_IP_PROTO_EN;
	cmd->enc_auth_mode = mlx_ipsec_get_auth_identifier(sa->x) << 4;
	cmd->enc_auth_mode |= mlx_ipsec_get_crypto_identifier(sa->x);
	if (!(sa->x->xso.flags & XFRM_OFFLOAD_INBOUND))
		cmd->enable |= SADB_DIR_SX;
	if (sa->x->props.mode)
		cmd->enable |= SADB_TUNNEL | SADB_TUNNEL_EN;
	memcpy(cmd->key, sa->x->aead->alg_key, key_len);
	/* Duplicate 128 bit key twice according to HW layout */
	if (key_len == 16)
		memcpy(cmd->key + 16, sa->x->aead->alg_key, key_len);

	/* serialize fifo and mlx_accel_core_sendmsg */
	spin_lock_irqsave(&dev->fifo_sa_cmds_lock, flags);
	pr_debug("adding to fifo!\n");
	fifo_full = kfifo_put(&dev->fifo_sa_cmds, sa);
	spin_unlock_irqrestore(&dev->fifo_sa_cmds_lock, flags);

	if (!fifo_full)
		goto err_buf;

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
	module_put(THIS_MODULE);
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

#endif /* MLX_IPSEC_SADB_RDMA */
