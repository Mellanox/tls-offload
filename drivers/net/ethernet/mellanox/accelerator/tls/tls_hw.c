/*
 * Copyright (c) 2015-2017 Mellanox Technologies. All rights reserved.
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
#include "tls_hw.h"
#include "tls_cmds.h"
#include <linux/inetdevice.h>
#include <linux/socket.h>

static void mlx_tls_del_work(struct work_struct *w);

static DEFINE_SPINLOCK(tls_del_lock);
static DECLARE_WORK(tls_del_work, mlx_tls_del_work);
static LIST_HEAD(tls_del_list);

static int build_ctx(struct tls_crypto_info_aes_gcm_128 *crypto_info,
		     u32 expectedSN,
		     __be32 swid,
		     unsigned short skc_family,
		     struct inet_sock *inet,
		     struct tls_cntx *tls)
{
	if (skc_family != PF_INET6) {
		tls->tcp.ip_sa[3] = inet->inet_rcv_saddr;
		tls->tcp.ip_da[3] = inet->inet_daddr;
	} else {
#if IS_ENABLED(CONFIG_IPV6)
		memcpy((void *)tls->tcp.ip_sa,
		       inet->pinet6->saddr.in6_u.u6_addr8, 16);
		memcpy((void *)tls->tcp.ip_da,
		       inet->pinet6->daddr_cache->in6_u.u6_addr8, 16);
#endif
		pr_err("IPv6 isn't supported yet\n");
		return -EINVAL;
	}
	tls->tcp.flags |= htonl(TLS_TCP_IP_PROTO);
	tls->tcp.flags |= htonl(TLS_TCP_VALID);
	tls->tcp.flags |= htonl(TLS_TCP_INIT);
	tls->tcp.src_port = inet->inet_sport;
	tls->tcp.dst_port = inet->inet_dport;
	tls->tcp.sw_sa_id = swid;
	tls->tcp.tcp_sn = htonl(expectedSN);

	tls->rcd.rcd_tcp_sn_nxt = htonl(expectedSN);
//	tls->rcd.enc_auth_mode |= TLS_RCD_AUTH_AES_GCM128;
//	tls->rcd.enc_auth_mode |= TLS_RCD_ENC_AES_GCM128;
	tls->rcd.rcd_type_ver |= TLS_RCD_VER_1_2 << 4;

	memcpy(&tls->rcd.rcd_implicit_iv, crypto_info->salt,
	       TLS_CIPHER_AES_GCM_128_SALT_SIZE);
	memcpy(tls->rcd.rcd_sn, crypto_info->iv,
	       TLS_CIPHER_AES_GCM_128_IV_SIZE);
	memcpy(tls->crypto.enc_key, crypto_info->key,
	       TLS_CIPHER_AES_GCM_128_KEY_SIZE);
	memcpy(tls->crypto.enc_key + TLS_CIPHER_AES_GCM_128_KEY_SIZE,
	       crypto_info->key, TLS_CIPHER_AES_GCM_128_KEY_SIZE);

	return 0;
}

#ifdef MLX_TLS_SADB_RDMA
static int send_teardown_cmd(struct mlx_tls_dev *dev, __be32 swid)
{
	struct mlx_accel_core_dma_buf *buf;
	struct teardown_stream_cmd *cmd;
	int size = sizeof(*buf) + sizeof(*cmd);

	buf = kzalloc(size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	buf->data = buf + 1;
	buf->data_size = sizeof(*cmd);

	cmd = (struct teardown_stream_cmd *)buf->data;
	cmd->cmd = CMD_TEARDOWN_STREAM;
	cmd->stream_id = swid;

	return mlx_accel_core_sendmsg(dev->conn, buf);
}
#endif

static void mlx_tls_del_work(struct work_struct *w)
{
	struct mlx_tls_offload_context *context;
	struct mlx_tls_dev *dev;

	spin_lock_irq(&tls_del_lock);
	while (true) {
		context =
			list_first_entry_or_null(&tls_del_list,
						 struct mlx_tls_offload_context,
						 tls_del_list);
		spin_unlock_irq(&tls_del_lock);
		if (!context)
			break;

		dev = mlx_tls_find_dev_by_netdev(context->netdev);

#ifdef MLX_TLS_SADB_RDMA
		if (send_teardown_cmd(dev, context->swid)) {
			/* try again later */
			schedule_work(w);
			break;
		}
#endif

		ida_simple_remove(&dev->swid_ida, ntohl(context->swid));

		module_put(THIS_MODULE);

		spin_lock_irq(&tls_del_lock);
		list_del(&context->tls_del_list);
		kfree(context);
	}
}

void mlx_tls_hw_stop_cmd(struct net_device *netdev,
			 struct mlx_tls_offload_context *context)
{
	unsigned long flags;

	pr_info("mlx_tls_hw_stop_cmd\n");
	spin_lock_irqsave(&tls_del_lock, flags);
	list_add_tail(&context->tls_del_list, &tls_del_list);
	context->netdev = netdev;
	schedule_work(&tls_del_work);
	spin_unlock_irqrestore(&tls_del_lock, flags);
}

#ifndef MLX_TLS_SADB_RDMA
#include "../core/accel_core.h"

#define GW_CTRL_RW   htonl(BIT(29))
#define GW_CTRL_BUSY htonl(BIT(30))
#define GW_CTRL_LOCK htonl(BIT(31))

#define GW_CTRL_ADDR_SHIFT 26

static int mlx_accel_gw_waitfor(struct mlx5_core_dev *dev, u64 addr, u32 mask,
				u32 value)
{
	int ret = 0;
	u32 gw_value;
	int try = 0;
	static const int max_tries = 100;

	while (true) {
		pr_debug("Waiting for %x/%x. Try %d\n", value, mask, try);
		ret = mlx5_fpga_access_reg(dev, sizeof(u32), addr,
					   (u8 *)&gw_value, false);
		if (ret)
			return ret;

		pr_debug("Value is %x\n", gw_value);
		if ((gw_value & mask) == value)
			break; //lock is taken automatically if it was 0.
		try++;
		if (try >= max_tries) {
			pr_debug("Timeout waiting for %x/%x at %llx. Value is %x after %d tries\n",
				 value, mask, addr, gw_value, try);
			return -EBUSY;
		}
		usleep_range(10, 100);
	};
	return 0;
}

static int mlx_accel_gw_lock(struct mlx5_core_dev *dev, u64 addr)
{
	return mlx_accel_gw_waitfor(dev, addr, GW_CTRL_LOCK, 0);
}

static int mlx_accel_gw_unlock(struct mlx5_core_dev *dev, u64 addr)
{
	u32 gw_value;
	int ret;

	pr_debug("Unlocking %llx\n", addr);
	ret = mlx5_fpga_access_reg(dev, sizeof(u32), addr,
				   (u8 *)&gw_value, false);
	if (ret)
		return ret;

	if ((gw_value & GW_CTRL_LOCK) != GW_CTRL_LOCK)
		pr_warn("Lock expected when unlocking, but not held for device %s addr %llx\n",
			dev->priv.name, addr);

	pr_debug("Old value %x\n", gw_value);
	gw_value &= ~GW_CTRL_LOCK;
	pr_debug("New value %x\n", gw_value);
	ret = mlx5_fpga_access_reg(dev, sizeof(u32), addr,
				   (u8 *)&gw_value, true);
	if (ret)
		return ret;
	return 0;
}

static int mlx_accel_gw_op(struct mlx5_core_dev *dev, u64 addr,
			   unsigned int index, bool write)
{
	u32 gw_value;
	int ret;

	if (index >= 8)
		pr_warn("Trying to access index %u out of range for GW at %llx\n",
			index, addr);

	pr_debug("Performing op %u at %llx\n", write, addr);
	ret = mlx5_fpga_access_reg(dev, sizeof(u32), addr,
				   (u8 *)&gw_value, false);
	if (ret)
		return ret;

	pr_debug("Old op value is %x\n", gw_value);
	if ((gw_value & GW_CTRL_LOCK) != GW_CTRL_LOCK)
		pr_warn("Lock expected for %s, but not held for device %s addr %llx\n",
			write ? "write" : "read", dev->priv.name, addr);

	gw_value &= htonl(~(7 << GW_CTRL_ADDR_SHIFT));
	gw_value |= htonl(index << GW_CTRL_ADDR_SHIFT);
	if (write)
		gw_value &= ~GW_CTRL_RW;
	else
		gw_value |= GW_CTRL_RW;

	gw_value |= GW_CTRL_BUSY;

	pr_debug("New op value is %x\n", gw_value);
	ret = mlx5_fpga_access_reg(dev, sizeof(u32), addr,
				   (u8 *)&gw_value, true);
	if (ret)
		return ret;

	return mlx_accel_gw_waitfor(dev, addr, GW_CTRL_BUSY, 0);
}

static int mlx_accel_gw_write(struct mlx5_core_dev *dev, u64 addr,
			      unsigned int index)
{
	return mlx_accel_gw_op(dev, addr, index, true);
}

#define CRSPACE_TCP_BASE 0x0
#define CRSPACE_TCP_OFFSET 0x10
#define CRSPACE_RECORD_BASE 0x100
#define CRSPACE_RECORD_OFFSET 0xc
#define CRSPACE_CRYPTO_BASE 0x180
#define CRSPACE_CRYPTO_OFFSET 0x10

static void write_context(struct mlx5_core_dev *dev, void *ctx,
			  size_t size, u64 base, u32 offset) {
	mlx_accel_gw_lock(dev, base);
	mlx5_fpga_access_reg(dev, size, base + offset, ctx, true);
	mlx_accel_gw_write(dev, base, 0);
	mlx_accel_gw_unlock(dev, base);
}

int mlx_tls_hw_start_cmd(struct mlx_tls_dev *dev, struct sock *sk,
			 bool is_send,
			 struct tls_crypto_info_aes_gcm_128 *crypto_info,
			 struct mlx_tls_offload_context *context)
{
	struct tls_cntx tls;
	int ret;
	struct inet_sock *inet = inet_sk(sk);
	u32 expectedSN = context->context.expectedSN;

	memset(&tls, 0, sizeof(tls));

	ret = build_ctx(crypto_info,
			expectedSN,
			context->swid,
			sk->sk_family,
			inet,
			&tls);
	if (ret)
		return ret;

	write_context(dev->accel_device->hw_dev,
		      &tls.rcd,
		      sizeof(tls.rcd),
		      CRSPACE_RECORD_BASE,
		      CRSPACE_RECORD_OFFSET);

	write_context(dev->accel_device->hw_dev,
		      &tls.crypto,
		      sizeof(tls.crypto),
		      CRSPACE_CRYPTO_BASE,
		      CRSPACE_CRYPTO_OFFSET);

	write_context(dev->accel_device->hw_dev,
		      &tls.tcp,
		      sizeof(tls.tcp),
		      CRSPACE_TCP_BASE,
		      CRSPACE_TCP_OFFSET);
	return 0;
}

#else /* MLX_TLS_SADB_RDMA */
static DEFINE_SPINLOCK(setup_stream_lock);
static LIST_HEAD(setup_stream_list);
struct setup_stream_t {
	struct list_head list;
	__be32 swid;
	struct completion x;
};

static void mlx_accel_core_kfree_complete(struct mlx_accel_core_conn *conn,
					  struct mlx_accel_core_dma_buf *buf,
					  struct ib_wc *wc)
{
	kfree(buf);
}

int mlx_tls_hw_start_cmd(struct mlx_tls_dev *dev,
			 struct sock *sk,
			 bool is_send,
			 struct tls_crypto_info_aes_gcm_128 *crypto_info,
			 struct mlx_tls_offload_context *context)
{
	struct mlx_accel_core_dma_buf *buf;
	struct setup_stream_cmd *cmd;
	struct inet_sock *inet = inet_sk(sk);
	u32 expectedSN = context->context.expectedSN;
	int ret;
	int size = sizeof(*buf) + sizeof(*cmd);
	struct setup_stream_t ss;

	buf = kzalloc(size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	buf->data = buf + 1;
	buf->data_size = sizeof(*cmd);
	buf->complete = mlx_accel_core_kfree_complete;

	cmd = (struct setup_stream_cmd *)buf->data;
	cmd->cmd = CMD_SETUP_STREAM;
	cmd->stream_id = context->swid;

	ret = build_ctx(crypto_info,
			expectedSN,
			context->swid,
			sk->sk_family,
			inet,
			&cmd->tls);
	if (ret) {
		kfree(buf);
		return ret;
	}

	ss.swid = context->swid;
	init_completion(&ss.x);
	spin_lock_irq(&setup_stream_lock);
	list_add_tail(&ss.list, &setup_stream_list);
	spin_unlock_irq(&setup_stream_lock);

	mlx_accel_core_sendmsg(dev->conn, buf);
	ret = wait_for_completion_killable(&ss.x);
	if (ret) {
		spin_lock_irq(&setup_stream_lock);
		list_del(&ss.list);
		spin_unlock_irq(&setup_stream_lock);
	}

	return ret;
}

static void handle_setup_stream_response(__be32 swid)
{
	struct setup_stream_t *ss;
	unsigned long flags;

	spin_lock_irqsave(&setup_stream_lock, flags);
	list_for_each_entry(ss, &setup_stream_list, list) {
		if (ss->swid == swid) {
			list_del(&ss->list);
			complete(&ss->x);
			break;
		}
	}
	spin_unlock_irqrestore(&setup_stream_lock, flags);
}

void mlx_tls_hw_qp_recv_cb(void *cb_arg,
			   struct mlx_accel_core_dma_buf *buf)
{
	struct generic_event *ev = (struct generic_event *)buf->data;

	switch (ev->opcode) {
	case htonl(EVENT_SETUP_STREAM_RESPONSE):
		handle_setup_stream_response(ev->stream_id);
		break;
	default:
		pr_warn("mlx_tls_hw_qp_recv_cb: unexpected event opcode %u\n",
			ntohl(ev->opcode));
	}
}

#endif /* MLX_TLS_SADB_RDMA */
