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

#include <linux/etherdevice.h>
#include <linux/mlx5_ib/driver.h>
#include <linux/mlx5/driver.h>
#include <linux/mlx5/vport.h>
#include <rdma/ib_mad.h>

#include "fpga.h"
#include "accel_core.h"

static int mlx_accel_core_rdma_close_qp(struct mlx_accel_core_conn *conn);
static void mlx_accel_core_rdma_destroy_res(struct mlx_accel_core_conn *conn);

static void mlx_accel_core_recv_complete(struct mlx_accel_core_conn *conn,
					 struct mlx_accel_core_dma_buf *buf,
					 struct ib_wc *wc)
{
	mlx_accel_dbg(conn->accel_device, "Free buf %p\n", buf);
	kfree(buf);
}

static int mlx_accel_core_rdma_post_recv(struct mlx_accel_core_conn *conn)
{
	struct ib_sge sge;
	struct ib_recv_wr wr;
	struct ib_recv_wr *bad_wr;
	struct mlx_accel_core_dma_buf *buf;
	int rc;

	buf = kmalloc(sizeof(*buf) + MLX_RECV_SIZE, 0);
	if (!buf)
		return -ENOMEM;

	memset(buf, 0, sizeof(*buf));
	buf->data = ((u8 *)buf + sizeof(*buf));
	buf->data_size = MLX_RECV_SIZE;
	buf->data_dma_addr = ib_dma_map_single(conn->accel_device->ib_dev,
					       buf->data, buf->data_size,
					       DMA_FROM_DEVICE);

	if (ib_dma_mapping_error(conn->accel_device->ib_dev,
				 buf->data_dma_addr)) {
		mlx_accel_warn(conn->accel_device, "post_recv: DMA mapping error on address %p\n",
			       buf->data);
		return -ENOMEM;
	}

	buf->dma_dir = DMA_FROM_DEVICE;
	buf->complete = mlx_accel_core_recv_complete;

	memset(&sge, 0, sizeof(sge));
	sge.addr = buf->data_dma_addr;
	sge.length = buf->data_size;
	sge.lkey = conn->accel_device->pd->local_dma_lkey;

	/* prepare the send work request (SR) */
	memset(&wr, 0, sizeof(wr));
	wr.next		= NULL;
	wr.sg_list	= &sge;
	wr.num_sge	= 1;
	wr.wr_id	= (uint64_t)buf;

	atomic_inc(&conn->pending_recvs);
	rc = ib_post_recv(conn->qp, &wr, &bad_wr);
	if (rc) {
		atomic_dec(&conn->pending_recvs);
		ib_dma_unmap_single(conn->accel_device->ib_dev,
				    buf->data_dma_addr, buf->data_size,
				    DMA_FROM_DEVICE);
		kfree(buf);
		goto out;
	}
	mlx_accel_dbg(conn->accel_device, "Posted RECV buf %p\n", buf);

out:
	return rc;
}

int mlx_accel_core_rdma_post_send(struct mlx_accel_core_conn *conn,
				  struct mlx_accel_core_dma_buf *buf)
{
	struct ib_device *ib_dev = conn->accel_device->ib_dev;
	struct ib_sge sge[2];
	struct ib_send_wr wr;
	struct ib_send_wr *bad_wr;
	int rc;
	int sge_count = 1;

	buf->dma_dir = DMA_TO_DEVICE;

	if (buf->more) {
		buf->more_dma_addr = ib_dma_map_single(ib_dev, buf->more,
						       buf->more_size,
						       DMA_TO_DEVICE);
		if (ib_dma_mapping_error(ib_dev, buf->more_dma_addr)) {
			mlx_accel_warn(conn->accel_device, "sendmsg: DMA mapping error on header address %p\n",
				       buf->more);
			rc = -ENOMEM;
			goto out;
		}
	}
	buf->data_dma_addr = ib_dma_map_single(ib_dev, buf->data,
					       buf->data_size, DMA_TO_DEVICE);
	if (ib_dma_mapping_error(ib_dev, buf->data_dma_addr)) {
		mlx_accel_warn(conn->accel_device, "sendmsg: DMA mapping error on address %p\n",
			       buf->data);
		rc = -ENOMEM;
		goto out_header_dma;
	}

	memset(&sge, 0, sizeof(sge));
	sge[0].addr = buf->data_dma_addr;
	sge[0].length = buf->data_size;
	sge[0].lkey = conn->accel_device->pd->local_dma_lkey;
	if (buf->more) {
		sge[sge_count].addr = buf->more_dma_addr;
		sge[sge_count].length = buf->more_size;
		sge[sge_count].lkey = conn->accel_device->pd->local_dma_lkey;
		sge_count++;
	}

	/* prepare the send work request (SR) */
	memset(&wr, 0, sizeof(wr));
	wr.next		= NULL;
	wr.sg_list	= sge;
	wr.num_sge	= sge_count;
	wr.wr_id	= (uint64_t)buf;
	wr.opcode	= IB_WR_SEND;
	wr.send_flags	= IB_SEND_SIGNALED;

	atomic_inc(&conn->inflight_sends);
	pr_debug("Posting SEND buf %p\n", buf);
#ifdef DEBUG
	print_hex_dump_bytes("SEND Data ", DUMP_PREFIX_OFFSET,
			     buf->data, buf->data_size);
	if (buf->more)
		print_hex_dump_bytes("SEND More ", DUMP_PREFIX_OFFSET,
				     buf->more, buf->more_size);
#endif

	rc = ib_post_send(conn->qp, &wr, &bad_wr);
	if (rc) {
		mlx_accel_dbg(conn->accel_device, "SEND buf %p post failed: %d\n",
			      buf, rc);
		atomic_dec(&conn->inflight_sends);
		goto out_dma;
	}
	goto out;

out_dma:
	ib_dma_unmap_single(ib_dev, buf->data_dma_addr, buf->data_size,
			    DMA_TO_DEVICE);
out_header_dma:
	ib_dma_unmap_single(ib_dev, buf->more_dma_addr, buf->more_size,
			    DMA_TO_DEVICE);
out:
	return rc;
}

static void mlx_accel_core_rdma_handle_pending(struct mlx_accel_core_conn *conn)
{
	struct mlx_accel_core_dma_buf *buf;
	int rc;

	spin_lock(&conn->pending_lock);
	while (1) {
		buf = list_first_entry_or_null(&conn->pending_msgs,
					       struct mlx_accel_core_dma_buf,
					       list);
		spin_unlock(&conn->pending_lock);
		if (!buf)
			break;

		rc = mlx_accel_core_rdma_post_send(conn, buf);
		if (rc)
			break;

		spin_lock(&conn->pending_lock);
		list_del(&buf->list);
	}
}

static void mlx_accel_complete(struct mlx_accel_core_conn *conn,
			       struct ib_wc *wc)
{
	struct mlx_accel_core_dma_buf *buf;

	if ((wc->status != IB_WC_SUCCESS) &&
	    (conn->exiting) && (wc->wr_id == MLX_EXIT_WRID)) {
		mlx_accel_dbg(conn->accel_device, "QP exiting %u; wr_id is %llx\n",
			      conn->exiting, wc->wr_id);
		if (++conn->exiting >= 3)
			complete(&conn->exit_completion);
		return;
	}
	buf = (struct mlx_accel_core_dma_buf *)wc->wr_id;
	if ((wc->status != IB_WC_SUCCESS) && (wc->status != IB_WC_WR_FLUSH_ERR))
		mlx_accel_warn(conn->accel_device,
			       "QP returned buf %p with vendor error %d status msg: %s\n",
			       buf, wc->vendor_err,
			       ib_wc_status_msg(wc->status));
	else
		mlx_accel_dbg(conn->accel_device,
			      "Completion of buf %p opcode %u status %d: %s\n",
			      buf, wc->opcode, wc->vendor_err,
			      ib_wc_status_msg(wc->status));

	ib_dma_unmap_single(conn->accel_device->ib_dev,
			    buf->data_dma_addr,
			    buf->data_size,
			    buf->dma_dir);
	if (buf->more) {
		ib_dma_unmap_single(conn->accel_device->ib_dev,
				    buf->more_dma_addr,
				    buf->more_size,
				    buf->dma_dir);
	}
	if (wc->status == IB_WC_SUCCESS) {
		switch (wc->opcode) {
		case IB_WC_RECV:
			atomic_dec(&conn->pending_recvs);
			buf->data_size = wc->byte_len;
#ifdef DEBUG
			print_hex_dump_bytes("RECV Data ",
					     DUMP_PREFIX_OFFSET, buf->data,
					     buf->data_size);
			if (buf->more)
				print_hex_dump_bytes("RECV More ",
						     DUMP_PREFIX_OFFSET,
						     buf->more, buf->more_size);
#endif
			conn->recv_cb(conn->cb_arg, buf);
			pr_debug("Msg with %u bytes received successfully %d buffs are posted\n",
				 wc->byte_len,
				 atomic_read(&conn->pending_recvs));
			break;
		case IB_WC_SEND:
			atomic_dec(&conn->inflight_sends);
			pr_debug("Msg sent successfully; %d send msgs inflight\n",
				 atomic_read(&conn->inflight_sends));
			break;
		default:
			pr_warn("Unknown wc opcode %d\n", wc->opcode);
		}
	}

	if (buf->complete)
		buf->complete(conn, buf, wc);
}

static void mlx_accel_core_rdma_comp_handler(struct ib_cq *cq, void *arg)
{
	struct mlx_accel_core_conn *conn = (struct mlx_accel_core_conn *)arg;
	struct ib_wc wc;
	int ret;
	bool continue_polling = true;

	pr_debug("-> Polling completions...\n");
	while (continue_polling) {
		continue_polling = false;
		while (ib_poll_cq(cq, 1, &wc) == 1) {
			if (wc.status == IB_WC_SUCCESS)
				continue_polling = true;
			mlx_accel_complete(conn, &wc);
		}

		if (continue_polling && !conn->exiting) {
			/* fill receive queue */
			while (!mlx_accel_core_rdma_post_recv(conn))
				;

			mlx_accel_core_rdma_handle_pending(conn);
		}
	}

	pr_debug("<- Requesting next completions\n");
	ret = ib_req_notify_cq(cq, IB_CQ_NEXT_COMP);
	if (ret)
		pr_warn("completion_handler: ib_req_notify_cq failed with error=%d\n",
			ret);
}

static int mlx_accel_core_rdma_create_res(struct mlx_accel_core_conn *conn,
					  unsigned int tx_size,
					  unsigned int rx_size)
{
	struct ib_cq_init_attr cq_attr = {0};
	struct ib_qp_init_attr qp_init_attr = {0};
	int rc = 0;

	cq_attr.cqe = 2 * (tx_size + rx_size);
	/* TODO: add event cb for cq */
	conn->cq = ib_create_cq(conn->accel_device->ib_dev,
			mlx_accel_core_rdma_comp_handler, NULL, conn, &cq_attr);
	if (IS_ERR(conn->cq)) {
		rc = PTR_ERR(conn->cq);
		pr_warn("Failed to create recv CQ\n");
		goto out;
	}

	ib_req_notify_cq(conn->cq, IB_CQ_NEXT_COMP);

	/*
	 * allocate QP
	 */
	qp_init_attr.cap.max_send_wr	= tx_size;
	qp_init_attr.cap.max_recv_wr	= rx_size;
	qp_init_attr.cap.max_recv_sge	= 1;
	qp_init_attr.cap.max_send_sge	= 2;
	qp_init_attr.sq_sig_type	= IB_SIGNAL_REQ_WR;
	qp_init_attr.qp_type		= IB_QPT_RC;
	qp_init_attr.send_cq		= conn->cq;
	qp_init_attr.recv_cq		= conn->cq;

	conn->qp = ib_create_qp(conn->accel_device->pd, &qp_init_attr);
	if (IS_ERR(conn->qp)) {
		rc = PTR_ERR(conn->qp);
		pr_warn("Failed to create QP\n");
		goto err_create_cq;
	}

	goto out;

err_create_cq:
	ib_destroy_cq(conn->cq);
out:
	return rc;
}

struct mlx_accel_core_conn *
mlx_accel_core_rdma_conn_create(struct mlx_accel_core_device *accel_device,
				struct mlx_accel_core_conn_init_attr *
				conn_init_attr, bool is_shell_conn)
{
	int err;
	struct mlx_accel_core_conn *ret = NULL;
	struct mlx_accel_core_conn *conn = NULL;
	union ib_gid *gid = NULL;

	conn = kzalloc(sizeof(*conn), GFP_KERNEL);
	if (!conn) {
		ret = ERR_PTR(-ENOMEM);
		goto err;
	}

	if (!conn_init_attr->recv_cb) {
		ret = ERR_PTR(-EINVAL);
		goto err;
	}

	conn->accel_device = accel_device;
	conn->port_num = accel_device->port;

	atomic_set(&conn->inflight_sends, 0);
	atomic_set(&conn->pending_recvs, 0);

	INIT_LIST_HEAD(&conn->pending_msgs);
	spin_lock_init(&conn->pending_lock);

	conn->recv_cb = conn_init_attr->recv_cb;
	conn->cb_arg = conn_init_attr->cb_arg;

	err = mlx5_query_nic_vport_mac_address(accel_device->hw_dev, 0,
					       conn->fpga_qpc.remote_mac);
	if (err) {
		pr_err("Failed to query local MAC: %d\n", err);
		goto err;
	}

	conn->fpga_qpc.remote_ip.s6_addr[0] = 0xfe;
	conn->fpga_qpc.remote_ip.s6_addr[1] = 0x80;
	conn->fpga_qpc.remote_ip.s6_addr[8] = conn->fpga_qpc.remote_mac[0] ^
					      0x02;
	conn->fpga_qpc.remote_ip.s6_addr[9] = conn->fpga_qpc.remote_mac[1];
	conn->fpga_qpc.remote_ip.s6_addr[10] = conn->fpga_qpc.remote_mac[2];
	conn->fpga_qpc.remote_ip.s6_addr[11] = 0xff;
	conn->fpga_qpc.remote_ip.s6_addr[12] = 0xfe;
	conn->fpga_qpc.remote_ip.s6_addr[13] = conn->fpga_qpc.remote_mac[3];
	conn->fpga_qpc.remote_ip.s6_addr[14] = conn->fpga_qpc.remote_mac[4];
	conn->fpga_qpc.remote_ip.s6_addr[15] = conn->fpga_qpc.remote_mac[5];

	pr_debug("Local gid is %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n",
		 ntohs(((__be16 *)&conn->fpga_qpc.remote_ip)[0]),
		 ntohs(((__be16 *)&conn->fpga_qpc.remote_ip)[1]),
		 ntohs(((__be16 *)&conn->fpga_qpc.remote_ip)[2]),
		 ntohs(((__be16 *)&conn->fpga_qpc.remote_ip)[3]),
		 ntohs(((__be16 *)&conn->fpga_qpc.remote_ip)[4]),
		 ntohs(((__be16 *)&conn->fpga_qpc.remote_ip)[5]),
		 ntohs(((__be16 *)&conn->fpga_qpc.remote_ip)[6]),
		 ntohs(((__be16 *)&conn->fpga_qpc.remote_ip)[7]));

	gid = (union ib_gid *)&conn->fpga_qpc.remote_ip;
	err = mlx5_ib_reserved_gid_add(accel_device->ib_dev, accel_device->port,
				       IB_GID_TYPE_ROCE_UDP_ENCAP,
				       gid, conn->fpga_qpc.remote_mac,
				       true,
				       0, &conn->sgid_index);
	if (err) {
		pr_warn("Failed to add reserved GID: %d\n", err);
		ret = ERR_PTR(err);
		goto err;
	}

	err = mlx_accel_core_rdma_create_res(conn,
					     conn_init_attr->tx_size,
					     conn_init_attr->rx_size);
	if (err) {
		ret = ERR_PTR(err);
		goto err_rsvd_gid;
	}

	conn->fpga_qpc.state = MLX5_FPGA_QP_STATE_INIT;
	conn->fpga_qpc.qp_type = is_shell_conn ? MLX5_FPGA_QP_TYPE_SHELL :
			MLX5_FPGA_QP_TYPE_SANDBOX;
	conn->fpga_qpc.st = MLX5_FPGA_QP_SERVICE_TYPE_RC;
	conn->fpga_qpc.ether_type = ETH_P_8021Q;
	conn->fpga_qpc.pkey = IB_DEFAULT_PKEY_FULL;
	conn->fpga_qpc.remote_qpn = conn->qp->qp_num;
	conn->fpga_qpc.rnr_retry = 7;
	conn->fpga_qpc.retry_count = 7;
	conn->fpga_qpc.vlan_id = 0;
	conn->fpga_qpc.next_rcv_psn = 1;
	conn->fpga_qpc.next_send_psn = 0;

	err = mlx5_fpga_create_qp(accel_device->hw_dev,
				  &conn->fpga_qpc,
				  &conn->fpga_qpn);
	if (err) {
		pr_err("Failed to create FPGA RC QP: %d\n", err);
		ret = ERR_PTR(err);
		goto err_create_res;
	}

	pr_debug("FPGA QPN is %u\n", conn->fpga_qpn);
	ret = conn;
	goto out;

err_create_res:
	mlx_accel_core_rdma_destroy_res(conn);
err_rsvd_gid:
	mlx5_ib_reserved_gid_del(accel_device->ib_dev, accel_device->port,
				 conn->sgid_index);
err:
	kfree(conn);
out:
	return ret;
}

static int mlx_accel_core_rdma_close_qp(struct mlx_accel_core_conn *conn)
{
	struct ib_recv_wr *bad_recv_wr, recv_wr = {0};
	struct ib_send_wr *bad_send_wr, send_wr = {0};
	struct ib_qp_attr attr = {0};
	struct ib_qp_init_attr init_attr = {0};
	int rc = 0, flags;

	conn->exiting = 1;

	rc = ib_query_qp(conn->qp, &attr, IB_QP_STATE, &init_attr);
	if (rc || (attr.qp_state == IB_QPS_RESET)) {
		pr_info("mlx_accel_core_close_qp: no need to modify state for ibdev %s\n",
				conn->accel_device->ib_dev->name);
		goto out;
	}

	pr_debug("mlx_accel_core_close_qp: curr qp state: %d", attr.qp_state);
	memset(&attr, 0, sizeof(attr));
	attr.qp_state = IB_QPS_ERR;
	flags = IB_QP_STATE;
	rc = ib_modify_qp(conn->qp, &attr, flags);
	if (rc) {
		pr_warn("mlx_accel_core_close_qp: ib_modify_qp failed ibdev %s err:%d\n",
			conn->accel_device->ib_dev->name, rc);
		goto out;
	}

	init_completion(&conn->exit_completion);
	recv_wr.wr_id = MLX_EXIT_WRID;
	while ((rc = ib_post_recv(conn->qp, &recv_wr, &bad_recv_wr)) == -ENOMEM)
		;
	if (rc) {
		pr_warn("mlx_accel_core_close_qp: posting recv failed\n");
		goto out;
	}
	send_wr.wr_id = MLX_EXIT_WRID;
	while ((rc = ib_post_send(conn->qp, &send_wr, &bad_send_wr)) == -ENOMEM)
		;
	if (rc) {
		pr_warn("mlx_accel_core_close_qp: posting send failed\n");
		goto out;
	}
	wait_for_completion(&conn->exit_completion);
out:
	rc = ib_destroy_qp(conn->qp);
	conn->qp = NULL;
	return rc;
}

static void mlx_accel_core_rdma_destroy_res(struct mlx_accel_core_conn *conn)
{
	int err = 0;

	mlx_accel_core_rdma_close_qp(conn);
	err = ib_destroy_cq(conn->cq);
	if (err)
		pr_warn("Failed to destroy CQ: %d\n", err);
}

void mlx_accel_core_rdma_conn_destroy(struct mlx_accel_core_conn *conn)
{
	mlx5_fpga_destroy_qp(conn->accel_device->hw_dev, conn->fpga_qpn);
	mlx_accel_core_rdma_destroy_res(conn);
	mlx5_ib_reserved_gid_del(conn->accel_device->ib_dev, conn->port_num,
				 conn->sgid_index);
	kfree(conn);
}

static inline int mlx_accel_core_rdma_init_qp(struct mlx_accel_core_conn *conn)
{
	struct ib_qp_attr attr = {0};
	int rc = 0;

	attr.qp_state = IB_QPS_INIT;
	attr.qp_access_flags = 0;
	attr.port_num = conn->port_num;
	attr.pkey_index = conn->accel_device->pkey_index;

	rc = ib_modify_qp(conn->qp, &attr,
				IB_QP_STATE		|
				IB_QP_PKEY_INDEX	|
				IB_QP_ACCESS_FLAGS	|
				IB_QP_PORT);

	return rc;
}

static inline int mlx_accel_core_rdma_reset_qp(struct mlx_accel_core_conn *conn)
{
	struct ib_qp_attr attr = {0};
	int rc = 0;

	attr.qp_state = IB_QPS_RESET;

	rc = ib_modify_qp(conn->qp, &attr, IB_QP_STATE);

	return rc;
}

static inline int mlx_accel_core_rdma_rtr_qp(struct mlx_accel_core_conn *conn)
{
	struct ib_qp_attr attr = {0};
	int rc = 0;

	attr.qp_state = IB_QPS_RTR;
	attr.path_mtu = IB_MTU_1024;
	attr.dest_qp_num = conn->fpga_qpn;
	attr.rq_psn = conn->fpga_qpc.next_send_psn;
	attr.max_dest_rd_atomic = 0;
	attr.min_rnr_timer = 0x12;
	attr.ah_attr.port_num = conn->port_num;
	attr.ah_attr.sl = 0;
	attr.ah_attr.ah_flags = IB_AH_GRH;
	memcpy(&attr.ah_attr.grh.dgid, &conn->fpga_qpc.fpga_ip,
	       sizeof(attr.ah_attr.grh.dgid));
	attr.ah_attr.grh.sgid_index = conn->sgid_index;
	pr_debug("Transition to RTR using sGID index %u\n", conn->sgid_index);

	rc = ib_modify_qp(conn->qp, &attr,
				IB_QP_STATE			|
				IB_QP_AV			|
				IB_QP_PATH_MTU			|
				IB_QP_DEST_QPN			|
				IB_QP_RQ_PSN			|
				IB_QP_MAX_DEST_RD_ATOMIC	|
				IB_QP_MIN_RNR_TIMER);

	return rc;
}

static inline int mlx_accel_core_rdma_rts_qp(struct mlx_accel_core_conn *conn)
{
	struct ib_qp_attr attr = {0};
	int rc = 0, flags;

	attr.qp_state		= IB_QPS_RTS;
	attr.timeout		= 0x12; /* 0x12 = ~1.07 sec */
	attr.retry_cnt		= 7;
	attr.rnr_retry		= 7; /* Infinite retry in case of RNR NACK */
	attr.sq_psn		= conn->fpga_qpc.next_rcv_psn;
	attr.max_rd_atomic	= 0;

	flags = IB_QP_STATE | IB_QP_TIMEOUT | IB_QP_RETRY_CNT |
			IB_QP_RNR_RETRY | IB_QP_SQ_PSN | IB_QP_MAX_QP_RD_ATOMIC;

	rc = ib_modify_qp(conn->qp, &attr, flags);

	return rc;
}

int mlx_accel_core_rdma_connect(struct mlx_accel_core_conn *conn)
{
	int rc = 0;

	conn->fpga_qpc.state = MLX5_FPGA_QP_STATE_ACTIVE;
	rc = mlx5_fpga_modify_qp(conn->accel_device->hw_dev,
				 conn->fpga_qpn,
				 MLX5_FPGA_QPC_STATE,
				 &conn->fpga_qpc);
	if (rc) {
		pr_warn("Failed to activate FPGA RC QP: %d\n", rc);
		goto err;
	}

	rc = mlx_accel_core_rdma_reset_qp(conn);
	if (rc) {
		pr_warn("Failed to change QP state to reset\n");
		goto err_fpga_qp;
	}

	rc = mlx_accel_core_rdma_init_qp(conn);
	if (rc) {
		pr_warn("Failed to modify QP from RESET to INIT\n");
		goto err_fpga_qp;
	}

	while (!mlx_accel_core_rdma_post_recv(conn))
		;

	rc = mlx_accel_core_rdma_rtr_qp(conn);
	if (rc) {
		pr_warn("Failed to change QP state from INIT to RTR\n");
		goto err_fpga_qp;
	}

	rc = mlx_accel_core_rdma_rts_qp(conn);
	if (rc) {
		pr_warn("Failed to change QP state from RTR to RTS\n");
		goto err_fpga_qp;
	}
	goto err;

err_fpga_qp:
	conn->fpga_qpc.state = MLX5_FPGA_QP_STATE_INIT;
	if (mlx5_fpga_modify_qp(conn->accel_device->hw_dev,
				conn->fpga_qpn, MLX5_FPGA_QPC_STATE,
				&conn->fpga_qpc))
		pr_warn("Failed to revert FPGA QP to INIT\n");
err:
	return rc;
}
