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

#include <rdma/ib_verbs.h>
#include <linux/types.h>
#include <linux/list.h>

#include "accel_core_sdk.h"


static LIST_HEAD(mlx_accel_core_ctx_list);
static LIST_HEAD(mlx_accel_core_devices);
static LIST_HEAD(mlx_accel_core_clients);
static DEFINE_MUTEX(mlx_accel_core_mutex);

#define MLX_RECV_SIZE 2048
#define MLX_EXIT_WRID 1

int mlx_accel_core_init_qp(struct mlx_accel_core_ctx *res);
int mlx_accel_core_reset_qp(struct mlx_accel_core_ctx *res);
int mlx_accel_core_rtr_qp(struct mlx_accel_core_ctx *res, int dqpn);
int mlx_accel_core_rts_qp(struct mlx_accel_core_ctx *res);
int mlx_accel_core_close_qp(struct mlx_accel_core_ctx *ctx);

int sendmsg(struct mlx_accel_core_ctx *ctx, struct mlx_accel_core_dma_buf *buf);

void mlx_accel_core_add_client_to_device(
		struct ib_device *device, u8 port,
		struct mlx_accel_core_client *client);

void mlx_accel_core_release(struct mlx_accel_core_ctx *ctx);

int post_recv(struct mlx_accel_core_ctx *ctx);

void completion_handler(struct ib_cq *cq, void *arg);

#endif /* __MLX_ACCEL_CORE_H__ */
