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


int mlx_accel_core_init_qp(struct mlx_accel_core_ctx *res)
{
	int ret = 0;
	struct ib_qp_attr attr = {};

	attr.qp_state = IB_QPS_INIT;
	/* TODO: do we need RDMA write? */
	attr.qp_access_flags = IB_ACCESS_REMOTE_WRITE;
	attr.port_num = res->port_num;
	/* TODO: Can we assume it will always be 0? */
	attr.pkey_index = 0;

	ret = ib_modify_qp(res->qp, &attr,
				IB_QP_STATE		|
				IB_QP_PKEY_INDEX	|
				IB_QP_ACCESS_FLAGS	|
				IB_QP_PORT);

	return ret;
}

int mlx_accel_core_reset_qp(struct mlx_accel_core_ctx *res)
{
	int ret = 0;
	struct ib_qp_attr attr;
	memset(&attr, 0, sizeof attr);

	attr.qp_state = IB_QPS_RESET;

	ret = ib_modify_qp(res->qp, &attr,
			IB_QP_STATE);

	return ret;
}

int mlx_accel_core_rtr_qp(struct mlx_accel_core_ctx *res, int dqpn)
{
	int ret = 0;
	struct ib_qp_attr attr;
	memset(&attr, 0, sizeof attr);

	pr_info("mlx_accel_core_rtr_qp\n");

	attr.qp_state = IB_QPS_RTR;
	attr.path_mtu = IB_MTU_1024;
	attr.dest_qp_num = dqpn;
	attr.rq_psn = 1;
	attr.max_rd_atomic = 0;
	attr.min_rnr_timer = 0x12;

	attr.ah_attr.port_num = res->port_num;
	attr.ah_attr.sl = res->sl;
	attr.ah_attr.ah_flags = IB_AH_GRH;
	attr.ah_attr.grh.dgid = res->dgid;

	ret = ib_modify_qp(res->qp, &attr,
			IB_QP_STATE			|
			IB_QP_AV			|
			IB_QP_PATH_MTU			|
			IB_QP_DEST_QPN			|
			IB_QP_RQ_PSN			|
			IB_QP_MAX_DEST_RD_ATOMIC	|
			IB_QP_MIN_RNR_TIMER);

	return ret;
}

int mlx_accel_core_rts_qp(struct mlx_accel_core_ctx *res)
{
	int ret = 0, flags;
	struct ib_qp_attr attr;
	memset(&attr, 0, sizeof(attr));
	pr_info("mlx_accel_core_rts_qp\n");

	attr.qp_state		= IB_QPS_RTS;
	attr.timeout		= 0x12;
	attr.retry_cnt		= 6;
	attr.rnr_retry		= 7;
	attr.sq_psn		= 1;
	attr.max_rd_atomic	= 0;

	flags = IB_QP_STATE | IB_QP_TIMEOUT | IB_QP_RETRY_CNT |
		IB_QP_RNR_RETRY | IB_QP_SQ_PSN | IB_QP_MAX_QP_RD_ATOMIC;

	ret = ib_modify_qp(res->qp, &attr,
			flags);

	return ret;
}

int sendmsg(struct mlx_accel_core_ctx *ctx, struct mlx_accel_core_dma_buf *buf)
{
	struct ib_sge sge;
	struct ib_send_wr wr;
	struct ib_send_wr *bad_wr;
	int ret;


	buf->dma_addr = ib_dma_map_single(ctx->ibdev,
							buf->data,
							buf->data_size,
							DMA_TO_DEVICE);
	buf->dma_dir = DMA_TO_DEVICE;

	if (ib_dma_mapping_error(ctx->ibdev, buf->dma_addr)) {
			pr_err("sendmsg: DMA mapping error on address %p\n",
					buf->data);
			return -ENOMEM;
	}

	memset(&sge, 0, sizeof(sge));
	sge.addr = buf->dma_addr;
	sge.length = buf->data_size;
	sge.lkey = ctx->mr->lkey;


	/* prepare the send work request (SR) */
	memset(&wr, 0, sizeof(wr));

	wr.next		= NULL;
	wr.wr_id	= 0;
	wr.sg_list	= &sge;
	wr.num_sge	= 1;
	wr.wr_id	= (uint64_t)buf;

	wr.opcode	= IB_WR_SEND;
	wr.send_flags	= IB_SEND_SIGNALED;

	ret = ib_post_send(ctx->qp, &wr, &bad_wr);
	if (ret == 0) {
		atomic_inc(&ctx->pending_sends);
	} else {
		/* panalize slow path rather then fast path */
		ib_dma_unmap_single(ctx->ibdev,
				buf->dma_addr,
				buf->data_size,
				DMA_TO_DEVICE);
	}

	return ret;
}

int post_recv(struct mlx_accel_core_ctx *ctx)
{
	struct ib_sge sge;
	struct ib_recv_wr wr;
	struct ib_recv_wr *bad_wr;
	struct mlx_accel_core_dma_buf *buf;
	int ret;
	memset(&sge, 0, sizeof(sge));
	sge.length = MLX_RECV_SIZE;
	buf = kmalloc(sizeof(struct mlx_accel_core_dma_buf) + sge.length, 0);
	if (!buf)
		return -ENOMEM;


	buf->data_size = sge.length;
	sge.addr = ib_dma_map_single(ctx->ibdev, buf->data, sge.length,
			DMA_FROM_DEVICE);

	if (ib_dma_mapping_error(ctx->ibdev, sge.addr)) {
		pr_err("post_recv: DMA mapping error on address %p\n",
				buf->data);
		return -ENOMEM;
	}

	buf->dma_addr = sge.addr;
	buf->dma_dir = DMA_FROM_DEVICE;

	sge.lkey = ctx->mr->lkey;

	/* prepare the send work request (SR) */
	memset(&wr, 0, sizeof(wr));

	wr.next		= NULL;
	wr.wr_id	= 0;
	wr.sg_list	= &sge;
	wr.num_sge	= 1;
	wr.wr_id	= (uint64_t)buf;

	ret = ib_post_recv(ctx->qp, &wr, &bad_wr);
	if (ret == 0)
		atomic_inc(&ctx->pending_recvs);
	else {
		ib_dma_unmap_single(ctx->ibdev,
				    buf->dma_addr,
				    buf->data_size,
				    DMA_FROM_DEVICE);
		kfree(buf);
	}
	return ret;
}

static void handle_pending(struct mlx_accel_core_ctx *ctx)
{
	struct mlx_accel_core_dma_buf *buf;
	int ret;

	spin_lock(&ctx->pending_lock);
	while (1) {
		buf = list_first_entry_or_null(&ctx->pending_msgs,
					       struct mlx_accel_core_dma_buf,
					       list);
		spin_unlock(&ctx->pending_lock);
		if (!buf)
			break;

		ret = sendmsg(ctx, buf);
		if (ret)
			break;

		spin_lock(&ctx->pending_lock);
		list_del(&buf->list);
	}
}

void completion_handler(struct ib_cq *cq, void *arg)
{
	struct mlx_accel_core_dma_buf *buf = NULL;
	struct mlx_accel_core_ctx *ctx = (struct mlx_accel_core_ctx *)arg;
	struct ib_wc wc;
	int ret;
	int contine_polling = 1;

	while (contine_polling) {
		contine_polling = 0;
		while (ib_poll_cq(cq, 1, &wc) == 1) {
			buf = (struct mlx_accel_core_dma_buf *)wc.wr_id;
			if (wc.status == IB_WC_SUCCESS) {
				contine_polling = 1;
				ib_dma_unmap_single(ctx->ibdev,
						buf->dma_addr,
						buf->data_size,
						buf->dma_dir);
				if (wc.opcode == IB_WC_RECV) {
					atomic_dec(&ctx->pending_recvs);
					buf->data_size = wc.byte_len;
					ctx->recv_cb(ctx->cb_arg, buf);
					pr_debug("Msg with %u bytes received successfully %d buffs are posted\n", wc.byte_len, atomic_read(&ctx->pending_recvs));
				} else if (wc.opcode == IB_WC_SEND) {
					kfree(buf);
					atomic_dec(&ctx->pending_sends);
					pr_debug("Msg sent successfully %d msgs pending\n", atomic_read(&ctx->pending_sends));
				} else {
					pr_err("Unknown wc opcode %d\n",
							wc.opcode);
				}

			} else {
				contine_polling = 0;
				if (ctx->exiting) {
					if (wc.wr_id == MLX_EXIT_WRID) {
						if (++ctx->exiting >= 3)
							complete(&ctx->exit_completion);
						continue;
					}
				} else {
					/* !ctx->exiting */
					pr_err("QP returned with vendor error %d status msg is-%s\n", wc.vendor_err, ib_wc_status_msg(wc.status));
				}

				ib_dma_unmap_single(ctx->ibdev,
						    buf->dma_addr,
						    buf->data_size,
						    buf->dma_dir);
				kfree(buf);
			}
		}


		if (contine_polling) {
			/* fill receive queue */
			while (!post_recv(ctx))
				;

			handle_pending(ctx);
		}
	}


	ret = ib_req_notify_cq(cq, IB_CQ_NEXT_COMP);
	if (ret)
		pr_info("completion_handler: ib_req_notify_cq failed with error=%d\n",
				ret);
}

int mlx_accel_core_close_qp(struct mlx_accel_core_ctx *ctx)
{
	int ret = 0, flags;
	struct ib_qp_attr attr;
	struct ib_recv_wr *bad_recv_wr, recv_wr = {};
	struct ib_send_wr *bad_send_wr, send_wr = {};

	struct ib_qp_attr qp_attr;
	struct ib_qp_init_attr query_init_attr;
	memset(&attr, 0, sizeof(attr));
	attr.qp_state = IB_QPS_ERR;
	flags = IB_QP_STATE;


	ctx->exiting = 1;

	ret = ib_query_qp(ctx->qp, &qp_attr, IB_QP_STATE, &query_init_attr);
	if (ret || (qp_attr.qp_state == IB_QPS_RESET)) {
		pr_info("mlx_accel_core_close_qp: no need to modify state for "
				"ibdev %s\n", ctx->ibdev->name);
		goto out;
	}

	pr_info("mlx_accel_core_close_qp: curr qp state: %d",
				qp_attr.qp_state);


	ret = ib_modify_qp(ctx->qp, &attr,
					flags);
	if (ret) {
		pr_info("mlx_accel_core_close_qp: ib_modify_qp failed ibdev %s err:%d\n",
				ctx->ibdev->name, ret);
		goto out;
	}

	init_completion(&ctx->exit_completion);
	recv_wr.wr_id = MLX_EXIT_WRID;
	while ((ret = ib_post_recv(ctx->qp, &recv_wr, &bad_recv_wr)) == -ENOMEM)
		;
	if (ret) {
		pr_info("mlx_accel_core_close_qp: posting recv failed\n");
		goto out;
	}
	send_wr.wr_id = MLX_EXIT_WRID;
	while ((ret = ib_post_send(ctx->qp, &send_wr, &bad_send_wr)) == -ENOMEM)
		;
	if (ret) {
		pr_info("mlx_accel_core_close_qp: posting send failed\n");
		goto out;
	}
	wait_for_completion(&ctx->exit_completion);
out:
	ret = ib_destroy_qp(ctx->qp);
	ctx->qp = NULL;
	return ret;
}
