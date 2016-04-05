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


u8 mlx_accel_core_get_port_num(struct mlx_accel_core_ctx *ctx)
{
	return ctx->port_num;
}
EXPORT_SYMBOL(mlx_accel_core_get_port_num);

struct ib_port {
	struct kobject         kobj;
	struct ib_device      *ibdev;
	struct attribute_group gid_group;
	struct attribute_group pkey_group;
	u8                     port_num;
};

struct kobject *
mlx_accel_core_get_kobject_parent(struct mlx_accel_core_ctx *ctx)
{
	u8 port_num = ctx->port_num;
	struct kobject *p = NULL, *result = NULL;

	list_for_each_entry(p, &ctx->ibdev->port_list, entry) {
		struct ib_port *port = container_of(p, struct ib_port, kobj);
			if (port->port_num == port_num) {
				result = &port->kobj;
				break;
			}
	}

	return result;
}
EXPORT_SYMBOL(mlx_accel_core_get_kobject_parent);

struct ib_device *mlx_accel_core_get_ibdev(struct mlx_accel_core_ctx *ctx)
{
	return ctx->ibdev;
}
EXPORT_SYMBOL(mlx_accel_core_get_ibdev);

void mlx_accel_core_register_client(struct mlx_accel_core_client *client)
{
	u8 port = 0;
	struct mlx_accel_core_accel_device *accel_device = NULL;

	pr_info("mlx_accel_core_register_client called\n");

	mutex_lock(&mlx_accel_core_mutex);
	list_add_tail(&client->list, &mlx_accel_core_clients);

	list_for_each_entry(accel_device, &mlx_accel_core_devices, list) {
		for (port = rdma_start_port(accel_device->device);
		     port <= rdma_end_port(accel_device->device);
		     port++) {
			/* [BP]: TODO: Add a check of client properties
			 * against the device properties and decide whether to
			 * create a context for this combination of client and
			 * device
			 */
			mlx_accel_core_add_client_to_device(
					accel_device->device,
					port, client);
		}
	}
	mutex_unlock(&mlx_accel_core_mutex);
}
EXPORT_SYMBOL(mlx_accel_core_register_client);

void mlx_accel_core_unregister_client(struct mlx_accel_core_client *client)
{
	struct mlx_accel_core_ctx *ctx = NULL, *tmp = NULL;

	pr_info("mlx_accel_core_unregister_client called\n");

	mutex_lock(&mlx_accel_core_mutex);
	list_del(&client->list);

	list_for_each_entry_safe(ctx, tmp, &mlx_accel_core_ctx_list, list) {
		if (!strncmp(ctx->client->name, client->name,
					IB_DEVICE_NAME_MAX))
			client->remove(ctx);
			mlx_accel_core_release(ctx);
	}
	mutex_unlock(&mlx_accel_core_mutex);
}
EXPORT_SYMBOL(mlx_accel_core_unregister_client);

int mlx_accel_core_create(struct mlx_accel_core_ctx *res,
		int tx_size, int rx_size,
		void (*recv_cb)(void *cb_arg,
				struct mlx_accel_core_dma_buf *buf),
		void *cb_arg)
{
	int ret = 0;
	struct ib_cq_init_attr cq_attr = {};
	struct ib_qp_init_attr init_attr = {};

	if (recv_cb == NULL)
		return -EINVAL;

	res->recv_cb = recv_cb;
	res->cb_arg = cb_arg;
	spin_lock_init(&res->pending_lock);
	INIT_LIST_HEAD(&res->pending_msgs);

	atomic_set(&res->pending_sends, 0);
	atomic_set(&res->pending_recvs, 0);

/* the allocated size is actully larger than the requested size */
	cq_attr.cqe = 4*tx_size + rx_size;
	res->cq = ib_create_cq(res->ibdev, completion_handler, NULL, res,
			&cq_attr);
	if (IS_ERR(res->cq)) {
		ret = PTR_ERR(res->cq);
		pr_err("Failed to create recv CQ\n");
		goto err;
	}

	ib_req_notify_cq(res->cq, IB_CQ_NEXT_COMP);

	res->pd = ib_alloc_pd(res->ibdev);
	if (IS_ERR(res->pd)) {
		ret = PTR_ERR(res->pd);
		pr_err("Failed to create PD\n");
		goto err_create_cq;
	}

	res->mr = ib_get_dma_mr(res->pd,
				IB_ACCESS_LOCAL_WRITE |
				IB_ACCESS_REMOTE_WRITE);
	if (IS_ERR(res->mr)) {
		ret = PTR_ERR(res->mr);
		pr_err("Failed to create mr\n");
		goto err_create_pd;
	}


	init_attr.cap.max_send_wr     = tx_size;
	init_attr.cap.max_recv_wr     = rx_size;
	init_attr.cap.max_recv_sge    = 1;
	init_attr.cap.max_send_sge    = 1;
	init_attr.sq_sig_type         = IB_SIGNAL_REQ_WR;
	init_attr.qp_type             = IB_QPT_RC;
	init_attr.send_cq             = res->cq;
	init_attr.recv_cq             = res->cq;

	res->qp = ib_create_qp(res->pd, &init_attr);
	if (IS_ERR(res->qp)) {
		ret = PTR_ERR(res->qp);
		pr_err("Failed to create QP\n");
		goto err_create_mr;
	}

	pr_info("created qp with %d send entries and %d recv entries\n",
			init_attr.cap.max_send_wr, init_attr.cap.max_recv_wr);

	return ret;

err_create_mr:
	ib_dereg_mr(res->mr);
err_create_pd:
	ib_dealloc_pd(res->pd);
err_create_cq:
	ib_destroy_cq(res->cq);
err:
	return ret;
}
EXPORT_SYMBOL(mlx_accel_core_create);

/* Must hold mlx_accel_core_ctx_list_mutex */
void mlx_accel_core_release(struct mlx_accel_core_ctx *ctx)
{
	struct mlx_accel_core_dma_buf *buf, *tmp;

	pr_info("mlx_accel_core_release called\n");

	list_del(&ctx->list);
	if (ctx->qp) {
		mlx_accel_core_close_qp(ctx);
		list_for_each_entry_safe(buf, tmp, &ctx->pending_msgs, list) {
			kfree(buf);
		}
		ib_destroy_cq(ctx->cq);
		ib_dereg_mr(ctx->mr);
		ib_dealloc_pd(ctx->pd);

	}

	kfree(ctx);
}
EXPORT_SYMBOL(mlx_accel_core_release);

int mlx_accel_core_connect(struct mlx_accel_core_ctx *ctx, int dqpn)
{
	int ret = 0;
	ret = mlx_accel_core_reset_qp(ctx);
	if (ret) {
		pr_err("Failed to change QP state to reset\n");
		return ret;
	}

	ret = mlx_accel_core_init_qp(ctx);
	if (ret) {
		pr_err("Failed to modify QP from RESET to INIT\n");
		return ret;
	}

	while (!post_recv(ctx))
		;

	ret = mlx_accel_core_rtr_qp(ctx, dqpn);
	if (ret) {
		pr_err("Failed to change QP state from INIT to RTR\n");
		return ret;
	}

	ret = mlx_accel_core_rts_qp(ctx);
	if (ret) {
		pr_err("Failed to change QP state from RTR to RTS\n");
		return ret;
	}

	return ret;
}
EXPORT_SYMBOL(mlx_accel_core_connect);

void mlx_accel_core_sendmsg(struct mlx_accel_core_ctx *ctx,
		struct mlx_accel_core_dma_buf *buf)
{
/* [I.L] TODO: see if the list_empty without lock is safe here */
	if (!list_empty(&ctx->pending_msgs) || sendmsg(ctx, buf)) {
		unsigned long flags;
		spin_lock_irqsave(&ctx->pending_lock, flags);
		list_add_tail(&buf->list, &ctx->pending_msgs);
		spin_unlock_irqrestore(&ctx->pending_lock, flags);
	}
}
EXPORT_SYMBOL(mlx_accel_core_sendmsg);
