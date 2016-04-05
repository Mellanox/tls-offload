/*
 * Copyright (c) 2015 Mellanox Technologies. All rights reserved.
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
#include <rdma/ib_verbs.h>
#include <linux/types.h>
#include <linux/module.h>
#include <uapi/linux/if_ether.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/sched.h>


#include "mlx_accel_core.h"


/* [BP]: TODO - change these details */
MODULE_AUTHOR("Jhon Snow <Jhon@WinterIsComing.com>");
MODULE_DESCRIPTION("Mellanox FPGA Accelerator Core Driver");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION("0.1");

#define RECV_SIZE 2048
#define EXIT_WRID 1

static LIST_HEAD(mlx_accel_core_clients);
static LIST_HEAD(mlx_accel_core_ctx_list);
static LIST_HEAD(mlx_accel_core_devices);
static DEFINE_MUTEX(mlx_accel_core_mutex);

struct ib_port;

struct gid_attr_group {
	struct ib_port		*port;
	struct kobject		kobj;
	struct attribute_group	ndev;
	struct attribute_group	type;
};

struct ib_port {
	struct kobject         kobj;
	struct ib_device      *ibdev;
	struct gid_attr_group *gid_attr_group;
	struct attribute_group gid_group;
	struct attribute_group pkey_group;
	u8                     port_num;
	struct attribute_group *pma_table;
};

u8 mlx_accel_core_get_port_num(struct mlx_accel_core_ctx *ctx)
{
	return ctx->port_num;
}
EXPORT_SYMBOL(mlx_accel_core_get_port_num);

struct kobject *mlx_accel_core_get_kobject_parent(struct mlx_accel_core_ctx *ctx)
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

/* called with mlx_accel_core_mutex locked */
void mlx_accel_core_add_client_to_device(
		struct ib_device *device, u8 port,
		struct mlx_accel_core_client *client)
{
	struct mlx_accel_core_ctx *ctx = NULL;

	pr_info("mlx_accel_core_add_client_to_device called\n");
	if (!client->add) {
		pr_err("Client must have an add function\n");
		return;
	}

	if (!client->remove) {
		pr_err("Client must have an add function\n");
		return;
	}

	ctx             = kzalloc(sizeof(*ctx), GFP_ATOMIC);
	if (!ctx)
		return;

	ctx->ibdev      = device;
	ctx->port_num   = port;
	ctx->client = client;
	list_add_tail(&ctx->list, &mlx_accel_core_ctx_list);
	pr_info("mlx_accel_core_add_client_to_device add called\n");
	client->add(ctx);
}

static void mlx_accel_core_add_one(struct ib_device *device)
{
	u8 port = 0;
	struct mlx_accel_core_client *client = NULL;
	struct mlx_accel_core_accel_device *accel_device =
		kmalloc(sizeof(*accel_device), GFP_ATOMIC);

	pr_info("mlx_accel_core_add_one called\n");

	if (!accel_device)
		return;

	accel_device->device = device;
	/* [BP]: TODO: get the FPGA properties */
	accel_device->properties = 0;

	mutex_lock(&mlx_accel_core_mutex);
	list_add_tail(&accel_device->list, &mlx_accel_core_devices);

	for (port = rdma_start_port(device); port <= rdma_end_port(device);
	     port++) {
		list_for_each_entry(client, &mlx_accel_core_clients, list) {
			/* [BP]: TODO: Add a check of client properties
			 * against the device properties and decide whether to
			 * create a context for this combination of client and
			 * device
			 */
			mlx_accel_core_add_client_to_device(device, port,
					client);
		}
	}
	mutex_unlock(&mlx_accel_core_mutex);
}

static void mlx_accel_core_remove_one(struct ib_device *device,
		void *client_data)
{
	struct mlx_accel_core_ctx *ctx = NULL, *tmp = NULL;
	struct mlx_accel_core_accel_device *accel_device;

	pr_info("mlx_accel_core_remove_one called for %s\n",device->name);

	mutex_lock(&mlx_accel_core_mutex);
	list_for_each_entry(accel_device, &mlx_accel_core_devices, list) {
		if (strncmp(accel_device->device->name, device->name,
					IB_DEVICE_NAME_MAX)) {
			continue;
		}
		list_del(&accel_device->list);
		break;
	}

	list_for_each_entry_safe(ctx, tmp, &mlx_accel_core_ctx_list, list) {
		/* If it's not the device being removed continue */
		if (strncmp(ctx->ibdev->name, device->name,
					IB_DEVICE_NAME_MAX))
			continue;
		/* Remove the device from its clients */
		ctx->client->remove(ctx);
		mlx_accel_core_release(ctx);
	}
	mutex_unlock(&mlx_accel_core_mutex);
}

static struct ib_client mlx_accel_core_ib_client = {
	.name   = "mlx_accel_core",
	.add    = mlx_accel_core_add_one,
	.remove = mlx_accel_core_remove_one
};

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

static inline int mlx_accel_core_init_qp(struct mlx_accel_core_ctx *res)
{
	int ret = 0;
	struct ib_qp_attr attr = {};

	attr.qp_state = IB_QPS_INIT;
	//TODO: do we need RDMA write?
	attr.qp_access_flags = IB_ACCESS_REMOTE_WRITE;
	attr.port_num = res->port_num;
	attr.pkey_index = 0;	 	//TODO: Can we assume it will always be 0?

	ret = ib_modify_qp(res->qp, &attr,
				IB_QP_STATE 		|
				IB_QP_PKEY_INDEX 	|
				IB_QP_ACCESS_FLAGS	|
				IB_QP_PORT);

	return ret;
}


static inline int mlx_accel_core_reset_qp(struct mlx_accel_core_ctx *res)
{
	int ret = 0;
	struct ib_qp_attr attr;
	memset(&attr, 0, sizeof attr);

	attr.qp_state = IB_QPS_RESET;

	ret = ib_modify_qp(res->qp, &attr,
			IB_QP_STATE);

	return ret;
}

static inline int mlx_accel_core_rtr_qp(struct mlx_accel_core_ctx *res, int dqpn)
{
	int ret = 0;
	struct ib_qp_attr attr;
	memset(&attr, 0, sizeof attr);

	printk("mlx_accel_core_rtr_qp\n");


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
			IB_QP_STATE 				|
			IB_QP_AV					|
			IB_QP_PATH_MTU				|
			IB_QP_DEST_QPN				|
			IB_QP_RQ_PSN				|
			IB_QP_MAX_DEST_RD_ATOMIC 	|
			IB_QP_MIN_RNR_TIMER);
			
	return ret;
}


static inline int mlx_accel_core_rts_qp(struct mlx_accel_core_ctx *res)
{
	int ret = 0, flags;
	struct ib_qp_attr attr;
	memset(&attr, 0, sizeof(attr));
	printk("mlx_accel_core_rts_qp\n");

	attr.qp_state 		= IB_QPS_RTS;
	attr.timeout 		= 0x12;
	attr.retry_cnt 		= 6;
	attr.rnr_retry 		= 7;
	attr.sq_psn 		= 1;
	attr.max_rd_atomic 	= 0;

 	flags = IB_QP_STATE | IB_QP_TIMEOUT | IB_QP_RETRY_CNT | 
		IB_QP_RNR_RETRY | IB_QP_SQ_PSN | IB_QP_MAX_QP_RD_ATOMIC;

 	ret = ib_modify_qp(res->qp, &attr,
 			flags);

	return ret;
}

static int sendmsg(struct mlx_accel_core_ctx *ctx,
		struct mlx_accel_core_dma_buf *buf)
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
			pr_err("sendmsg: DMA mapping error on address %p\n", buf->data);
			return -ENOMEM;
	}

	memset(&sge, 0, sizeof(sge));
	sge.addr = buf->dma_addr;
	sge.length = buf->data_size;
	sge.lkey = ctx->mr->lkey;


	/* prepare the send work request (SR) */
	memset(&wr, 0, sizeof(wr));

	wr.next 	= NULL;
	wr.wr_id 	= 0;
	wr.sg_list 	= &sge;
	wr.num_sge 	= 1;
	wr.wr_id = (uint64_t) buf;

	wr.opcode     = IB_WR_SEND;
	wr.send_flags = IB_SEND_SIGNALED;

	ret = ib_post_send(ctx->qp, &wr, &bad_wr);
	if (ret == 0) {
		atomic_inc(&ctx->pending_sends);
	}
	else {
		/* panalize slow path rather then fast path */
		ib_dma_unmap_single(ctx->ibdev,
				buf->dma_addr,
				buf->data_size,
				DMA_TO_DEVICE);
	}

	return ret;
}


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

static int post_recv(struct mlx_accel_core_ctx *ctx) {
	struct ib_sge sge;
	struct ib_recv_wr wr;
	struct ib_recv_wr *bad_wr;
	struct mlx_accel_core_dma_buf *buf;
	int ret;
	memset(&sge, 0, sizeof(sge));
	sge.length = RECV_SIZE;
	buf = kmalloc(sizeof(struct mlx_accel_core_dma_buf) + sge.length, 0);
	if (!buf)
		return -ENOMEM;


	buf->data_size = sge.length;
	sge.addr = ib_dma_map_single(ctx->ibdev,
								buf->data,
								sge.length,
								DMA_FROM_DEVICE);

	if (ib_dma_mapping_error(ctx->ibdev, sge.addr)) {
		pr_err("post_recv: DMA mapping error on address %p\n", buf->data);
		return -ENOMEM;
	}

	buf->dma_addr = sge.addr;
	buf->dma_dir = DMA_FROM_DEVICE;

	sge.lkey = ctx->mr->lkey;

	/* prepare the send work request (SR) */
	memset(&wr, 0, sizeof(wr));

	wr.next 	= NULL;
	wr.wr_id 	= 0;
	wr.sg_list 	= &sge;
	wr.num_sge 	= 1;
	wr.wr_id = (uint64_t) buf;

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

int mlx_accel_core_connect(struct mlx_accel_core_ctx *ctx, int dqpn)
{
	int ret = 0;
	ret = mlx_accel_core_reset_qp(ctx);
	if (ret) {
		pr_err("Failed to change QP state to reset\n");
		return ret;
	}

	ret = mlx_accel_core_init_qp(ctx);
	if(ret) {
		pr_err("Failed to modify QP from RESET to INIT\n");
		return ret;
	}

	while(!post_recv(ctx)) ;

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

static void handle_pending(struct mlx_accel_core_ctx *ctx) {
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

static void completion_handler(struct ib_cq *cq, void *arg)
{
	struct mlx_accel_core_ctx *ctx = (struct mlx_accel_core_ctx *)arg;
	struct ib_wc wc;
	int ret;
	int contine_polling = 1;
	while (contine_polling) {
		contine_polling = 0;
		while (ib_poll_cq(cq, 1, &wc) == 1){
			struct mlx_accel_core_dma_buf *buf =
					(struct mlx_accel_core_dma_buf *)wc.wr_id;
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
					pr_err("Unknown wc opcode %d\n", wc.opcode);
				}

			} else {
				contine_polling = 0;
				if (ctx->exiting) {
					if (wc.wr_id == EXIT_WRID) {
						if (++ctx->exiting >= 3)
							complete(&ctx->exit_completion);
						continue;
					}
				}
				else {
					//!ctx->exiting
					pr_err("QP returned with vendor error %d status msg is-%s\n"
							, wc.vendor_err ,ib_wc_status_msg(wc.status));
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
			while (!post_recv(ctx)) ;

			handle_pending(ctx);
		}
	}


	ret = ib_req_notify_cq(cq, IB_CQ_NEXT_COMP);
	if (ret)
		pr_info("completion_handler: ib_req_notify_cq failed with error=%d\n", ret);
}

static inline int mlx_accel_core_close_qp(struct mlx_accel_core_ctx *ctx)
{
	int ret = 0, flags;
	struct ib_qp_attr attr;
	struct ib_recv_wr *bad_recv_wr, recv_wr =  {};
	struct ib_send_wr *bad_send_wr, send_wr =  {};

	struct ib_qp_attr qp_attr;
	struct ib_qp_init_attr query_init_attr;
	memset(&attr, 0, sizeof(attr));
	attr.qp_state 		= IB_QPS_ERR;
 	flags = IB_QP_STATE;


 	ctx->exiting = 1;

	ret = ib_query_qp(ctx->qp, &qp_attr, IB_QP_STATE, &query_init_attr);
	if (ret || (qp_attr.qp_state== IB_QPS_RESET)) {
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
	recv_wr.wr_id = EXIT_WRID;
 	while ((ret = ib_post_recv(ctx->qp, &recv_wr, &bad_recv_wr)) == -ENOMEM) ;
 	if (ret) {
 		pr_info("mlx_accel_core_close_qp: posting recv failed\n");
		goto out;
 	}
	send_wr.wr_id = EXIT_WRID;
 	while ((ret = ib_post_send(ctx->qp, &send_wr, &bad_send_wr)) == -ENOMEM) ;
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

int mlx_accel_core_create(struct mlx_accel_core_ctx *res, int tx_size, int rx_size,
		void (*recv_cb)(void *cb_arg, struct mlx_accel_core_dma_buf *buf),
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

	atomic_set(&res->pending_sends,0);
	atomic_set(&res->pending_recvs,0);

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

static int __init mlx_accel_core_init(void)
{
	ib_register_client(&mlx_accel_core_ib_client);
	return 0;
}

static void __exit mlx_accel_core_exit(void)
{
	ib_unregister_client(&mlx_accel_core_ib_client);
}

module_init(mlx_accel_core_init);
module_exit(mlx_accel_core_exit);
