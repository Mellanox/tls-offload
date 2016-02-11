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

#include "accel_core.h"


static int mlx_accel_core_rdma_post_recv(struct mlx_accel_core_conn *conn)
{
	struct ib_sge sge;
	struct ib_recv_wr wr;
	struct ib_recv_wr *bad_wr;
	struct mlx_accel_core_dma_buf *buf;
	int rc;

	memset(&sge, 0, sizeof(sge));
	sge.length = MLX_RECV_SIZE;
	buf = kmalloc(sizeof(*buf) + sge.length, 0);
	if (!buf)
		return -ENOMEM;

	buf->data_size = sge.length;
	sge.addr = ib_dma_map_single(conn->accel_device->device,
					buf->data, sge.length,
					DMA_FROM_DEVICE);

	if (ib_dma_mapping_error(conn->accel_device->device, sge.addr)) {
		pr_err("post_recv: DMA mapping error on address %p\n",
				buf->data);
		return -ENOMEM;
	}

	buf->dma_addr = sge.addr;
	buf->dma_dir = DMA_FROM_DEVICE;

	sge.lkey = conn->mr->lkey;

	/* prepare the send work request (SR) */
	memset(&wr, 0, sizeof(wr));

	wr.next		= NULL;
	wr.wr_id	= 0;
	wr.sg_list	= &sge;
	wr.num_sge	= 1;
	wr.wr_id	= (uint64_t)buf;

	rc = ib_post_recv(conn->qp, &wr, &bad_wr);
	if (rc == 0)
		atomic_inc(&conn->pending_recvs);
	else {
		ib_dma_unmap_single(conn->accel_device->device, buf->dma_addr,
				buf->data_size, DMA_FROM_DEVICE);
		kfree(buf);
	}
	return rc;
}

int mlx_accel_core_rdma_post_send(struct mlx_accel_core_conn *conn,
		struct mlx_accel_core_dma_buf *buf)
{
	struct ib_sge sge;
	struct ib_send_wr wr;
	struct ib_send_wr *bad_wr;
	int rc;

	buf->dma_addr = ib_dma_map_single(conn->accel_device->device,
							buf->data,
							buf->data_size,
							DMA_TO_DEVICE);
	buf->dma_dir = DMA_TO_DEVICE;

	if (ib_dma_mapping_error(conn->accel_device->device, buf->dma_addr)) {
			pr_err("sendmsg: DMA mapping error on address %p\n",
					buf->data);
			return -ENOMEM;
	}

	memset(&sge, 0, sizeof(sge));
	sge.addr = buf->dma_addr;
	sge.length = buf->data_size;
	sge.lkey = conn->mr->lkey;


	/* prepare the send work request (SR) */
	memset(&wr, 0, sizeof(wr));
	wr.next		= NULL;
	wr.wr_id	= 0;
	wr.sg_list	= &sge;
	wr.num_sge	= 1;
	wr.wr_id	= (uint64_t)buf;
	wr.opcode	= IB_WR_SEND;
	wr.send_flags	= IB_SEND_SIGNALED;

	rc = ib_post_send(conn->qp, &wr, &bad_wr);
	if (!rc) {
		atomic_inc(&conn->pending_sends);
	} else {
		/* panalize slow path rather then fast path */
		ib_dma_unmap_single(conn->accel_device->device, buf->dma_addr,
					buf->data_size, DMA_TO_DEVICE);
	}

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

static void mlx_accel_core_rdma_comp_handler(struct ib_cq *cq, void *arg)
{
	struct mlx_accel_core_dma_buf *buf = NULL;
	struct mlx_accel_core_conn *conn = (struct mlx_accel_core_conn *)arg;
	struct ib_wc wc;
	int ret;
	int contine_polling = 1;

	while (contine_polling) {
		contine_polling = 0;
		while (ib_poll_cq(cq, 1, &wc) == 1) {
			buf = (struct mlx_accel_core_dma_buf *)wc.wr_id;
			if (wc.status == IB_WC_SUCCESS) {
				contine_polling = 1;
				ib_dma_unmap_single(conn->accel_device->device,
						buf->dma_addr,
						buf->data_size,
						buf->dma_dir);
				if (wc.opcode == IB_WC_RECV) {
					atomic_dec(&conn->pending_recvs);
					buf->data_size = wc.byte_len;
					conn->recv_cb(conn->cb_arg, buf);
					pr_debug("Msg with %u bytes received successfully %d buffs are posted\n",
							wc.byte_len, atomic_read(&conn->pending_recvs));
				} else if (wc.opcode == IB_WC_SEND) {
					kfree(buf);
					atomic_dec(&conn->pending_sends);
					pr_debug("Msg sent successfully %d msgs pending\n",
							atomic_read(&conn->pending_sends));
				} else {
					pr_err("Unknown wc opcode %d\n",
							wc.opcode);
				}

			} else {
				contine_polling = 0;
				if (conn->exiting) {
					if (wc.wr_id == MLX_EXIT_WRID) {
						if (++conn->exiting >= 3)
							complete(&conn->exit_completion);
						continue;
					}
				} else {
					pr_err("QP returned with vendor error %d status msg is-%s\n",
							wc.vendor_err, ib_wc_status_msg(wc.status));
				}

				ib_dma_unmap_single(conn->accel_device->device,
							buf->dma_addr,
							buf->data_size,
							buf->dma_dir);
				kfree(buf);
			}
		}


		if (contine_polling) {
			/* fill receive queue */
			while (!mlx_accel_core_rdma_post_recv(conn))
				;

			mlx_accel_core_rdma_handle_pending(conn);
		}
	}

	ret = ib_req_notify_cq(cq, IB_CQ_NEXT_COMP);
	if (ret)
		pr_info("completion_handler: ib_req_notify_cq failed with error=%d\n",
				ret);
}

int mlx_accel_core_rdma_create_res(struct mlx_accel_core_conn *conn,
					unsigned int tx_size,
					unsigned int rx_size)
{
	struct ib_cq_init_attr cq_attr = {0};
	struct ib_qp_init_attr qp_init_attr = {0};
	int rc;

	/*
	 * query GID
	 */
	rc = ib_query_gid(conn->accel_device->device, conn->port_num,
			  0, &conn->gid, NULL);
	if (rc) {
		pr_err("Failed to query gid got error %d\n", rc);
		return rc;
	}

	/*
	 * allocate PD
	 */
	conn->pd = ib_alloc_pd(conn->accel_device->device);
	if (IS_ERR(conn->pd)) {
		rc = PTR_ERR(conn->pd);
		pr_err("Failed to create PD\n");
		goto err;
	}

	/*
	 * allocate MR
	 */
	conn->mr = ib_get_dma_mr(conn->pd,
				IB_ACCESS_LOCAL_WRITE |
				IB_ACCESS_REMOTE_WRITE);
	if (IS_ERR(conn->mr)) {
		rc = PTR_ERR(conn->mr);
		pr_err("Failed to create mr\n");
		goto err_create_pd;
	}

	/*
	 * allocate CQ
	 */
	/*
	 * TODO: the allocated size is actually larger than
	 *  the requested size
	 */
	cq_attr.cqe = 4 * tx_size + rx_size;
	/* TODO: add event cb for cq */
	conn->cq = ib_create_cq(conn->accel_device->device,
			mlx_accel_core_rdma_comp_handler, NULL, conn, &cq_attr);
	if (IS_ERR(conn->cq)) {
		rc = PTR_ERR(conn->cq);
		pr_err("Failed to create recv CQ\n");
		goto err_create_mr;
	}

	ib_req_notify_cq(conn->cq, IB_CQ_NEXT_COMP);

	/*
	 * allocate QP
	 */
	qp_init_attr.cap.max_send_wr	= tx_size;
	qp_init_attr.cap.max_recv_wr	= rx_size;
	qp_init_attr.cap.max_recv_sge	= 1;
	qp_init_attr.cap.max_send_sge	= 1;
	qp_init_attr.sq_sig_type	= IB_SIGNAL_REQ_WR;
	qp_init_attr.qp_type		= IB_QPT_RC;
	qp_init_attr.send_cq		= conn->cq;
	qp_init_attr.recv_cq		= conn->cq;

	conn->qp = ib_create_qp(conn->pd, &qp_init_attr);
	if (IS_ERR(conn->qp)) {
		rc = PTR_ERR(conn->qp);
		pr_err("Failed to create QP\n");
		goto err_create_cq;
	}

	return rc;
err_create_cq:
	ib_destroy_cq(conn->cq);
err_create_mr:
	ib_dereg_mr(conn->mr);
err_create_pd:
	ib_dealloc_pd(conn->pd);
err:
	return 0;
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
				conn->accel_device->device->name);
		goto out;
	}

	pr_info("mlx_accel_core_close_qp: curr qp state: %d", attr.qp_state);
	memset(&attr, 0, sizeof(attr));
	attr.qp_state = IB_QPS_ERR;
	flags = IB_QP_STATE;
	rc = ib_modify_qp(conn->qp, &attr, flags);
	if (rc) {
		pr_info("mlx_accel_core_close_qp: ib_modify_qp failed ibdev %s err:%d\n",
				conn->accel_device->device->name, rc);
		goto out;
	}

	init_completion(&conn->exit_completion);
	recv_wr.wr_id = MLX_EXIT_WRID;
	while ((rc = ib_post_recv(conn->qp, &recv_wr, &bad_recv_wr)) == -ENOMEM)
		;
	if (rc) {
		pr_info("mlx_accel_core_close_qp: posting recv failed\n");
		goto out;
	}
	send_wr.wr_id = MLX_EXIT_WRID;
	while ((rc = ib_post_send(conn->qp, &send_wr, &bad_send_wr)) == -ENOMEM)
		;
	if (rc) {
		pr_info("mlx_accel_core_close_qp: posting send failed\n");
		goto out;
	}
	wait_for_completion(&conn->exit_completion);
out:
	rc = ib_destroy_qp(conn->qp);
	conn->qp = NULL;
	return rc;
}

void mlx_accel_core_rdma_destroy_res(struct mlx_accel_core_conn *conn)
{
	mlx_accel_core_rdma_close_qp(conn);
	ib_destroy_cq(conn->cq);
	ib_dereg_mr(conn->mr);
	ib_dealloc_pd(conn->pd);
}

static inline int mlx_accel_core_rdma_init_qp(struct mlx_accel_core_conn *conn)
{
	struct ib_qp_attr attr = {0};
	int rc = 0;

	attr.qp_state = IB_QPS_INIT;
	/* TODO: do we need RDMA write? */
	attr.qp_access_flags = IB_ACCESS_REMOTE_WRITE;
	attr.port_num = conn->port_num;
	/* TODO: Can we assume it will always be 0? */
	attr.pkey_index = 0;

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
	attr.dest_qp_num = conn->dqpn;
	attr.rq_psn = 1;
	attr.max_rd_atomic = 0;
	attr.min_rnr_timer = 0x12;
	attr.ah_attr.port_num = conn->port_num;
	attr.ah_attr.sl = conn->sl;
	attr.ah_attr.ah_flags = IB_AH_GRH;
	attr.ah_attr.grh.dgid = conn->dgid;

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
	attr.timeout		= 0x12;
	attr.retry_cnt		= 6;
	attr.rnr_retry		= 7;
	attr.sq_psn		= 1;
	attr.max_rd_atomic	= 0;

	flags = IB_QP_STATE | IB_QP_TIMEOUT | IB_QP_RETRY_CNT |
			IB_QP_RNR_RETRY | IB_QP_SQ_PSN | IB_QP_MAX_QP_RD_ATOMIC;

	rc = ib_modify_qp(conn->qp, &attr, flags);

	return rc;
}

int mlx_accel_core_rdma_connect(struct mlx_accel_core_conn *conn)
{
	int rc = 0;
	rc = mlx_accel_core_rdma_reset_qp(conn);
	if (rc) {
		pr_err("Failed to change QP state to reset\n");
		return rc;
	}

	rc = mlx_accel_core_rdma_init_qp(conn);
	if (rc) {
		pr_err("Failed to modify QP from RESET to INIT\n");
		return rc;
	}

	while (!mlx_accel_core_rdma_post_recv(conn))
		;

	rc = mlx_accel_core_rdma_rtr_qp(conn);
	if (rc) {
		pr_err("Failed to change QP state from INIT to RTR\n");
		return rc;
	}

	rc = mlx_accel_core_rdma_rts_qp(conn);
	if (rc) {
		pr_err("Failed to change QP state from RTR to RTS\n");
		return rc;
	}

	return rc;
}
