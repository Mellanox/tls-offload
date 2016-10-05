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

#ifndef __MLX_ACCEL_CORE_H__
#define __MLX_ACCEL_CORE_H__

#ifdef CONFIG_MLX_ACCEL_QP_SIMULATOR
#define QP_SIMULATOR
#endif
#include "accel_core_sdk.h"
#include <linux/in6.h>

#define MLX_RECV_SIZE 2048
#define MLX_EXIT_WRID 1

struct mlx_accel_client_data {
	struct list_head  list;
	struct mlx_accel_core_client *client;
	void *data;
	bool added;
};

struct mlx_accel_client_data *
mlx_accel_client_context_create(struct mlx_accel_core_device *device,
				struct mlx_accel_core_client *client);
void mlx_accel_client_context_destroy(struct mlx_accel_core_device *device,
				      struct mlx_accel_client_data *context);
void mlx_accel_device_teardown(struct mlx_accel_core_device *accel_device);

/* RDMA */
struct mlx_accel_core_conn *
mlx_accel_core_rdma_conn_create(struct mlx_accel_core_device *accel_device,
				struct mlx_accel_core_conn_init_attr
				*conn_init_attr, bool is_shell_conn);
void mlx_accel_core_rdma_conn_destroy(struct mlx_accel_core_conn *conn);

int mlx_accel_core_rdma_post_send(struct mlx_accel_core_conn *conn,
				  struct mlx_accel_core_dma_buf *buf);

int mlx_accel_core_rdma_connect(struct mlx_accel_core_conn *conn);

/* I2C */
int mlx_accel_read_i2c(struct mlx5_core_dev *dev,
		       size_t size, u64 addr, u8 *buf);
int mlx_accel_write_i2c(struct mlx5_core_dev *dev,
			size_t size, u64 addr, u8 *buf);

/* fpga QP */
#define mlx_accel_fpga_qp_device_init(accel_device) 0
#define mlx_accel_fpga_qp_device_deinit(accel_device)

#if defined(QP_SIMULATOR)
#undef mlx_accel_fpga_qp_device_init
#undef mlx_accel_fpga_qp_device_deinit
int mlx_accel_fpga_qp_device_init(struct mlx_accel_core_device *accel_device);
int mlx_accel_fpga_qp_device_deinit(struct mlx_accel_core_device *accel_device);
#endif

#endif /* __MLX_ACCEL_CORE_H__ */
