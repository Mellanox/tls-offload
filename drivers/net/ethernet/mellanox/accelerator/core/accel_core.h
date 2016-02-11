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

#include "accel_core_sdk.h"


#define MLX_RECV_SIZE 2048
#define MLX_EXIT_WRID 1

int mlx_accel_core_rdma_post_send(struct mlx_accel_core_conn *conn,
				  struct mlx_accel_core_dma_buf *buf);

int mlx_accel_core_rdma_create_res(struct mlx_accel_core_conn *conn,
				   unsigned int tx_size, unsigned int rx_size);
void mlx_accel_core_rdma_destroy_res(struct mlx_accel_core_conn *conn);

int mlx_accel_core_rdma_connect(struct mlx_accel_core_conn *conn);

#endif /* __MLX_ACCEL_CORE_H__ */
