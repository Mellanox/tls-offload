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
#include "fpga/sdk.h"
#include "fpga/core.h"

struct mlx5_fpga_tls {
	struct mlx5_fpga_conn *conn;
};

int mlx5_fpga_build_tls_ctx(struct tls12_crypto_info_aes_gcm_128 *crypto_info,
			    enum tls_offload_ctx_dir direction,
			    u32 expected_seq, char *rcd_sn,
			    unsigned short skc_family, struct inet_sock *inet,
			    struct tls_cntx *tls)
{
	void *tcp = tls;
	void *rcd = tcp + MLX5_ST_SZ_BYTES(tls_cntx_tcp);

	if (skc_family != PF_INET6) {
		MLX5_SET(tls_cntx_tcp, tcp, ip_sa_31_0,
			 ntohl(inet->inet_rcv_saddr));
		MLX5_SET(tls_cntx_tcp, tcp, ip_da_31_0,
			 ntohl(inet->inet_daddr));
	} else {
		pr_err("IPv6 isn't supported yet\n");
		return -EINVAL;
	}
	MLX5_SET(tls_cntx_tcp, tcp, ip_ver, 1); //tcp
	MLX5_SET(tls_cntx_tcp, tcp, sa_vld, 1);
	MLX5_SET(tls_cntx_tcp, tcp, src_port, htons(inet->inet_sport));
	MLX5_SET(tls_cntx_tcp, tcp, dst_port, htons(inet->inet_dport));

	MLX5_SET(tls_cntx_rcd, rcd, crypto_mode, TLS_RCD_AUTH_AES_GCM128);

	MLX5_SET(tls_cntx_rcd, rcd, rcd_ver, TLS_RCD_VER_1_2);
	MLX5_SET(tls_cntx_rcd, rcd, iv_offset_op, 0);
	memcpy(MLX5_ADDR_OF(tls_cntx_rcd, rcd, rcd_sn_63_32), rcd_sn,
	       TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);

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

static int send_teardown_cmd(struct mlx5_core_dev *mdev, __be32 swid)
{
	struct mlx5_fpga_dma_buf *buf;
	struct teardown_stream_cmd *cmd;
	int size = sizeof(*buf) + sizeof(*cmd);

	buf = kzalloc(size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	cmd = (struct teardown_stream_cmd *)(buf + 1);
	cmd->cmd = CMD_TEARDOWN_STREAM;
	cmd->stream_id = swid;

	buf->sg[0].data = cmd;
	buf->sg[0].size = sizeof(*cmd);
	buf->complete = mlx_tls_kfree_complete;

	return mlx5_fpga_sbu_conn_sendmsg(mdev->fpga->tls->conn, buf);
}

void mlx5_fpga_tls_hw_stop_tx_cmd(struct mlx5e_priv *priv,
				  struct mlx_tls_offload_context *ctx)
{
	netdev_dbg(priv->netdev, "%s\n", __func__);

	send_teardown_cmd(priv->mdev, ctx->swid);

	ida_simple_remove(&priv->tls->tx_halloc, ntohl(ctx->swid));
}

static DEFINE_SPINLOCK(setup_stream_lock);
static LIST_HEAD(setup_stream_list);
struct setup_stream_t {
	struct list_head list;
	__be32 swid;
	struct completion x;
};

int
mlx5_fpga_tls_hw_start_cmd(struct mlx5_core_dev *mdev, struct sock *sk,
			   struct tls12_crypto_info_aes_gcm_128 *crypto_info,
			   enum tls_offload_ctx_dir direction, u32 expected_seq,
			   char *rcd_sn, u32 swid)
{
	struct mlx5_fpga_dma_buf *buf;
	struct setup_stream_cmd *cmd;
	struct inet_sock *inet = inet_sk(sk);
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
	cmd->stream_id = htonl(swid);

	ret = mlx5_fpga_build_tls_ctx(crypto_info, direction, expected_seq,
				      rcd_sn, sk->sk_family, inet, &cmd->tls);
	if (ret) {
		kfree(buf);
		return ret;
	}

	ss.swid = cmd->stream_id;
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
		pr_warn("%s: unexpected event opcode %u\n",
			__func__, ntohl(ev->opcode));
	}
}

int
mlx5_fpga_tls_hw_start_tx_cmd(struct mlx5_core_dev *mdev, struct sock *sk,
			      struct tls12_crypto_info_aes_gcm_128 *crypto_info,
			      u32 expected_seq, u32 swid)
{
	return mlx5_fpga_tls_hw_start_cmd(mdev, sk, crypto_info,
					  TLS_OFFLOAD_CTX_DIR_TX, expected_seq,
					  crypto_info->rec_seq, swid);
}

bool mlx5_fpga_is_tls_device(struct mlx5_core_dev *mdev)
{
	if (!mdev->fpga || !MLX5_CAP_GEN(mdev, fpga))
		return false;

	if (MLX5_CAP_FPGA(mdev, ieee_vendor_id) !=
	    MLX5_FPGA_CAP_SANDBOX_VENDOR_ID_MLNX)
		return false;

	if (MLX5_CAP_FPGA(mdev, sandbox_product_id) !=
	    MLX5_FPGA_CAP_SANDBOX_PRODUCT_ID_TLS)
		return false;

	if (MLX5_CAP_FPGA(mdev, sandbox_product_version) != 0)
		return false;

	return true;
}

int mlx5_fpga_tls_init(struct mlx5_core_dev *mdev)
{
	int err = 0;
	struct mlx5_fpga_conn_attr init_attr = {0};
	struct mlx5_fpga_device *fdev = mdev->fpga;
	struct mlx5_fpga_conn *conn;

	if (!mlx5_fpga_is_tls_device(mdev))
		return 0;

	fdev->tls = kzalloc(sizeof(*fdev->tls), GFP_KERNEL);
	if (!fdev->tls)
		return -ENOMEM;

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
	return err;
}

void mlx5_fpga_tls_cleanup(struct mlx5_core_dev *mdev)
{
	struct mlx5_fpga_device *fdev = mdev->fpga;

	if (!mlx5_fpga_is_tls_device(mdev))
		return;

	mlx5_fpga_sbu_conn_destroy(fdev->tls->conn);
	kfree(fdev->tls);
	fdev->tls = NULL;
}
