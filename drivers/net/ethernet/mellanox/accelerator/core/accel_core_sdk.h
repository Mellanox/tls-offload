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

#ifndef __MLX_ACCEL_CORE_SDK_H__
#define __MLX_ACCEL_CORE_SDK_H__


struct mlx_accel_core_ctx;

/* represents an accelerated ib_device */
struct mlx_accel_core_accel_device {
	struct ib_device *device;
	struct list_head list;
	unsigned int properties; /* put here which accelerator properties does
				    the device support */
};

struct mlx_accel_core_client {
	char *name;
	void (*add)    (struct mlx_accel_core_ctx *);
	void (*remove) (struct mlx_accel_core_ctx *);

	struct list_head list;
	unsigned int properties; /* put here which accelerator properties does
				    the client support */
};

struct mlx_accel_core_dma_buf {
	struct list_head list;
	u64 dma_addr;
	enum dma_data_direction dma_dir;
	size_t data_size;
	size_t offset;
	char data[];
};

struct mlx_accel_core_ctx {
	struct ib_device *ibdev;
	struct ib_qp *qp;
	struct ib_pd *pd;
	struct ib_mr *mr;
	struct ib_cq *cq;
	u8 port_num;
	u16 pkey;
	u8 sl;
	union ib_gid dgid;

	atomic_t pending_sends;
	atomic_t pending_recvs;

	struct list_head pending_msgs;
	spinlock_t pending_lock;

	struct list_head list;

	void (*recv_cb)(void *cb_arg, struct mlx_accel_core_dma_buf *buf);
	void *cb_arg;

	struct completion exit_completion;
	int exiting;

	struct mlx_accel_core_client *client;
};

u8 mlx_accel_core_get_port_num(struct mlx_accel_core_ctx *ctx);

struct kobject
*mlx_accel_core_get_kobject_parent(struct mlx_accel_core_ctx *ctx);

struct ib_device *mlx_accel_core_get_ibdev(struct mlx_accel_core_ctx *ctx);

void mlx_accel_core_register_client(struct mlx_accel_core_client *client);
void mlx_accel_core_unregister_client(struct mlx_accel_core_client *client);

int mlx_accel_core_create(struct mlx_accel_core_ctx *res,
		int tx_size, int rx_size,
		void (*recv_cb)(void *cb_arg,
				struct mlx_accel_core_dma_buf *buf),
		void *cb_arg);
void mlx_accel_core_release(struct mlx_accel_core_ctx *res);

int mlx_accel_core_connect(struct mlx_accel_core_ctx *res, int dqpn);

void mlx_accel_core_sendmsg(struct mlx_accel_core_ctx *ctx,
		struct mlx_accel_core_dma_buf *buf);

#endif /* __MLX_ACCEL_CORE_SDK_H__ */
