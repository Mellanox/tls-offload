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

#include <linux/inetdevice.h>
#include <net/inet_sock.h>
#include <linux/socket.h>
#include <linux/mlx5/device.h>
#include "fpga/tls.h"
#include "fpga/cmd.h"
#include "fpga/tls_cmds.h"
#include "fpga/sdk.h"
#include "fpga/core.h"

struct mlx5_fpga_tls {
	struct mlx5_fpga_conn *conn;
};

//#define RCD_SN_OFFSET

#ifdef RCD_SN_OFFSET
static void calc_rcd_sn_offset(void *p_diff, void *p_iv, void *p_rcd) {
	__be64 rcd_sn;
	__be64 iv;
	__be64 diff;

	memcpy(&rcd_sn, p_rcd, sizeof(rcd_sn));
	memcpy(&iv, p_iv, sizeof(iv));


	diff = cpu_to_be64(be64_to_cpu(iv) - be64_to_cpu(rcd_sn));
	memcpy(p_diff, &diff, sizeof(diff));;
}
#endif

static int build_ctx(struct tls12_crypto_info_aes_gcm_128 *crypto_info,
		     u32 expected_seq,
		     unsigned short skc_family,
		     struct inet_sock *inet,
		     struct tls_cntx *tls)
{
	void *tcp = tls;
	void *rcd = tcp + MLX5_ST_SZ_BYTES(tls_cntx_tcp);

	if (skc_family != PF_INET6) {
		MLX5_SET(tls_cntx_tcp, tcp, ip_sa_31_0, ntohl(inet->inet_rcv_saddr));
		MLX5_SET(tls_cntx_tcp, tcp, ip_da_31_0, ntohl(inet->inet_daddr));
	} else {
#if IS_ENABLED(CONFIG_IPV6) && 0
		memcpy((void *)tls->tcp.ip_sa,
		       inet->pinet6->saddr.in6_u.u6_addr8, 16);
		memcpy((void *)tls->tcp.ip_da,
		       inet->pinet6->daddr_cache->in6_u.u6_addr8, 16);
#endif
		pr_err("IPv6 isn't supported yet\n");
		return -EINVAL;
	}
	MLX5_SET(tls_cntx_tcp, tcp, ip_ver, 1); //tcp
	MLX5_SET(tls_cntx_tcp, tcp, sa_vld, 1);
	MLX5_SET(tls_cntx_tcp, tcp, src_port, htons(inet->inet_sport));
	MLX5_SET(tls_cntx_tcp, tcp, dst_port, htons(inet->inet_dport));

	MLX5_SET(tls_cntx_rcd, rcd, crypto_mode, TLS_RCD_AUTH_AES_GCM128);

	MLX5_SET(tls_cntx_rcd, rcd, rcd_ver, TLS_RCD_VER_1_2);
#ifdef RCD_SN_OFFSET
	MLX5_SET(tls_cntx_rcd, rcd, iv_offset_op, 1);
	calc_rcd_sn_offset(MLX5_ADDR_OF(tls_cntx_rcd, rcd, rcd_sn_63_32),
			   crypto_info->iv, crypto_info->rec_seq);
#else
	MLX5_SET(tls_cntx_rcd, rcd, iv_offset_op, 0);
	memcpy(MLX5_ADDR_OF(tls_cntx_rcd, rcd, rcd_sn_63_32),
	       crypto_info->rec_seq,
	       TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);
#endif

	MLX5_SET(tls_cntx_rcd, rcd, rcd_tcp_sn_nxt, expected_seq);
	MLX5_SET(tls_cntx_rcd, rcd, tcp_sn, expected_seq);

	memcpy(MLX5_ADDR_OF(tls_cntx_rcd, rcd, rcd_implicit_iv),
	       crypto_info->salt,
	       TLS_CIPHER_AES_GCM_128_SALT_SIZE);

	memcpy(MLX5_ADDR_OF(tls_cntx_rcd, rcd, crypto_key_255_224),
	       crypto_info->key,
	       TLS_CIPHER_AES_GCM_128_KEY_SIZE);
	/* in AES-GCM 128 we need to write the key twice */
	memcpy(MLX5_ADDR_OF(tls_cntx_rcd, rcd, crypto_key_127_96),
	       crypto_info->key,
	       TLS_CIPHER_AES_GCM_128_KEY_SIZE);

	return 0;
}

static void mlx_tls_kfree_complete(struct mlx5_fpga_conn *conn,
				   struct mlx5_fpga_device *fdev,
				   struct mlx5_fpga_dma_buf *buf, u8 status)
{
	kfree(buf);
}

#ifdef MLX_TLS_SADB_RDMA
static int send_teardown_cmd(struct mlx5_core_dev *mdev, __be32 swid)
{
	struct mlx5_fpga_dma_buf *buf;
	struct teardown_stream_cmd *cmd;
	int size = sizeof(*buf) + sizeof(*cmd);

	buf = kzalloc(size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	cmd = (struct teardown_stream_cmd *) (buf + 1);
	cmd->cmd = CMD_TEARDOWN_STREAM;
	cmd->stream_id = swid;

	buf->sg[0].data = cmd;
	buf->sg[0].size = sizeof(*cmd);
	buf->complete = mlx_tls_kfree_complete;

	return mlx5_fpga_sbu_conn_sendmsg(mdev->fpga->tls->conn, buf);
}
#endif

void mlx5_fpga_tls_hw_stop_cmd(
			struct net_device *netdev,
			struct mlx_tls_offload_context *context)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);
	pr_info("mlx5_fpga_tls_hw_stop_cmd\n");

#ifdef MLX_TLS_SADB_RDMA
	send_teardown_cmd(priv->mdev, context->swid);
#endif

	ida_simple_remove(&priv->tls->halloc, ntohl(context->swid));
}

#ifndef MLX_TLS_SADB_RDMA
#define GW_CTRL_RW   htonl(BIT(29))
#define GW_CTRL_BUSY htonl(BIT(30))
#define GW_CTRL_LOCK htonl(BIT(31))

#define GW_CTRL_ADDR_SHIFT 24

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

	if (index >= 32)
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

	gw_value &= htonl(~(0x1f << GW_CTRL_ADDR_SHIFT));
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

static int mlx_accel_gw_write(struct mlx5_core_dev *mdev, u64 addr,
			      unsigned int index)
{
	return mlx_accel_gw_op(mdev, addr, index, true);
}

#define CRSPACE_TCP_BASE 0x0
#define CRSPACE_TCP_OFFSET 0x18
#define CRSPACE_RECORD_BASE 0x100
#define CRSPACE_RECORD_OFFSET 0x28
//#define CRSPACE_CRYPTO_BASE 0x180
//#define CRSPACE_CRYPTO_OFFSET 0x10

static void write_context(struct mlx5_core_dev *mdev, int index, void *ctx,
			  int size, u64 base, u32 offset) {
	int ret;
	int chunk;

	mlx_accel_gw_lock(mdev, base);
	offset += base;
	while (size > 0) {
		chunk = MLX5_FPGA_ACCESS_REG_SIZE_MAX;
		if (size < chunk)
			chunk = size;
		ret = mlx5_fpga_access_reg(mdev, chunk, offset, ctx, true);
		if (ret) {
			pr_err("mlx5_fpga_access_reg failed, ret=%d\n", ret);
			goto out;
		}
		offset += MLX5_FPGA_ACCESS_REG_SIZE_MAX;
		ctx += MLX5_FPGA_ACCESS_REG_SIZE_MAX;
		size -= MLX5_FPGA_ACCESS_REG_SIZE_MAX;
	}

	mlx_accel_gw_write(mdev, base, index);
out:
	mlx_accel_gw_unlock(mdev, base);
}

static DEFINE_MUTEX(gw_lock);

int mlx5_fpga_tls_hw_start_cmd(
			struct mlx5_core_dev *mdev, struct sock *sk,
			struct tls12_crypto_info_aes_gcm_128 *crypto_info,
			struct mlx_tls_offload_context *context)
{
	struct tls_cntx tls;
	int ret;
	struct inet_sock *inet = inet_sk(sk);
	u32 expectedSN = context->context.expectedSN;

	memset(&tls, 0, sizeof(tls));

	ret = build_ctx(crypto_info,
			expectedSN,
			sk->sk_family,
			inet,
			&tls);
	if (ret)
		return ret;

	mutex_lock(&gw_lock);
	write_context(mdev,
		      ntohl(context->swid),
		      tls.ctx + MLX5_ST_SZ_BYTES(tls_cntx_tcp),
		      MLX5_ST_SZ_BYTES(tls_cntx_rcd),
		      CRSPACE_RECORD_BASE,
		      CRSPACE_RECORD_OFFSET);

	write_context(mdev,
		      ntohl(context->swid),
		      tls.ctx,
		      MLX5_ST_SZ_BYTES(tls_cntx_tcp),
		      CRSPACE_TCP_BASE,
		      CRSPACE_TCP_OFFSET);
	mutex_unlock(&gw_lock);

	return 0;
}

#else //MLX_TLS_SADB_RDMA
static DEFINE_SPINLOCK(setup_stream_lock);
static LIST_HEAD(setup_stream_list);
struct setup_stream_t {
	struct list_head list;
	__be32 swid;
	struct completion x;
};

int mlx5_fpga_tls_hw_start_cmd(
			struct mlx5_core_dev *mdev, struct sock *sk,
			struct tls12_crypto_info_aes_gcm_128 *crypto_info,
			struct mlx_tls_offload_context *context)
{
	struct mlx5_fpga_dma_buf *buf;
	struct setup_stream_cmd *cmd;
	struct inet_sock *inet = inet_sk(sk);
	u32 expected_seq = context->context.expected_seq;
	int ret;
	int size = sizeof(*buf) + sizeof(*cmd);
	struct setup_stream_t ss;

	buf = kzalloc(size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	cmd = (struct setup_stream_cmd *)(buf + 1);
	buf->sg[0].data = buf + 1;
	buf->sg[0].size = sizeof(*cmd);
	buf->complete = mlx_tls_kfree_complete;


	cmd->cmd = CMD_SETUP_STREAM;
	cmd->stream_id = context->swid;

	ret = build_ctx(crypto_info,
			expected_seq,
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

	mlx5_fpga_sbu_conn_sendmsg(mdev->fpga->tls->conn, buf);
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
	int found = 0;

	spin_lock_irqsave(&setup_stream_lock, flags);
	list_for_each_entry(ss, &setup_stream_list, list) {
		if (ss->swid == swid) {
			list_del(&ss->list);
			complete(&ss->x);
			found = 1;
			break;
		}
	}
	spin_unlock_irqrestore(&setup_stream_lock, flags);

	if (!found)
		pr_err("Got unexpected setup stream response swid = %u\n",
		       ntohl(swid));
}

void mlx_tls_hw_qp_recv_cb(void *cb_arg, struct mlx5_fpga_dma_buf *buf)
{
	struct generic_event *ev = (struct generic_event *)buf->sg[0].data;

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

static bool mlx5_fpga_is_tls_device(struct mlx5_core_dev *mdev)
{
	if (!mdev->fpga || !MLX5_CAP_GEN(mdev, fpga))
		return false;

	if (MLX5_CAP_FPGA(mdev, ieee_vendor_id) !=
	    MLX5_FPGA_CAP_SANDBOX_VENDOR_ID_MLNX)
		return false;

	if (MLX5_CAP_FPGA(mdev, sandbox_product_id) !=
	    MLX5_FPGA_CAP_SANDBOX_PRODUCT_ID_TLS)
		return false;

	return true;
}

int mlx5_fpga_tls_init(struct mlx5_core_dev *mdev)
{
	int err = 0;
#ifdef MLX_TLS_SADB_RDMA
	struct mlx5_fpga_conn_attr init_attr = {0};
	struct mlx5_fpga_device *fdev = mdev->fpga;
	struct mlx5_fpga_conn *conn;
#endif

	if (!mlx5_fpga_is_tls_device(mdev))
		return 0;

#ifdef MLX_TLS_SADB_RDMA
	fdev->tls = kzalloc(sizeof(*fdev->tls), GFP_KERNEL);
	if (!fdev->tls)
		return -ENOMEM;

#if 0
	err = mlx5_fpga_get_sbu_caps(fdev, sizeof(fdev->ipsec->caps),
				     fdev->ipsec->caps);
	if (err) {
		mlx5_fpga_err(fdev, "Failed to retrieve IPSec extended capabilities: %d\n",
			      err);
		goto error;
	}

	INIT_LIST_HEAD(&fdev->ipsec->pending_cmds);
	spin_lock_init(&fdev->ipsec->pending_cmds_lock);
#endif

	init_attr.rx_size = SBU_QP_QUEUE_SIZE;
	init_attr.tx_size = SBU_QP_QUEUE_SIZE;
	init_attr.recv_cb = mlx_tls_hw_qp_recv_cb;
	init_attr.cb_arg = fdev;
	conn = mlx5_fpga_sbu_conn_create(fdev, &init_attr);
	if (IS_ERR(conn)) {
		err = PTR_ERR(conn);
		mlx5_fpga_err(fdev, "Error creating TLS command connection %d\n",
			      err);
		goto error;
	}
	fdev->tls->conn = conn;
	return 0;

error:
	kfree(fdev->tls);
	fdev->tls = NULL;
#endif
	return err;
}

void mlx5_fpga_tls_cleanup(struct mlx5_core_dev *mdev)
{
#ifdef MLX_TLS_SADB_RDMA
	struct mlx5_fpga_device *fdev = mdev->fpga;

	if (!mlx5_fpga_is_tls_device(mdev))
		return;

	mlx5_fpga_sbu_conn_destroy(fdev->tls->conn);
	kfree(fdev->tls);
	fdev->tls = NULL;
#endif
}
