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

#ifndef __MLX_ACCEL_CORE_TRANS_H__
#define __MLX_ACCEL_CORE_TRANS_H__

#include "accel_core.h"

#define MLX_ACCEL_TRANSACTION_MAX_SIZE	      1008
#define MLX_ACCEL_TRANSACTION_SEND_ALIGN_BITS 3
#define MLX_ACCEL_TRANSACTION_SEND_PAGE_BITS  12
#define MLX_ACCEL_TID_COUNT		      256

enum mlx_accel_direction {
	MLX_ACCEL_READ,
	MLX_ACCEL_WRITE,
};

enum mlx_accel_transaction_state {
	TRANS_STATE_NONE,
	TRANS_STATE_SEND,
	TRANS_STATE_WAIT,
	TRANS_STATE_COMPLETE,
};

struct mlx_accel_transaction_private {
	const struct mlx_accel_transaction *user_trans;
	u8 tid;
	enum mlx_accel_transaction_state state;
	enum ib_wc_status status;
	u32 header[MLX5_ST_SZ_DW(fpga_shell_qp_packet)];
	struct mlx_accel_core_dma_buf buf;
	struct list_head list_item;
};

struct mlx_accel_transaction {
	struct mlx_accel_core_conn *conn;
	enum mlx_accel_direction direction;
	size_t size;
	u64 addr;
	u8 *data;
	void (*complete)(const struct mlx_accel_transaction *complete,
			 enum ib_wc_status status);
};

struct mlx_accel_trans_device_state {
	spinlock_t lock; /* Protects all members of this struct */
	struct list_head free_queue;
	struct mlx_accel_transaction_private transactions[MLX_ACCEL_TID_COUNT];
};

int mlx_accel_trans_device_init(struct mlx_accel_core_device *accel_device);
void mlx_accel_trans_device_deinit(struct mlx_accel_core_device *accel_device);

int mlx_accel_trans_exec(const struct mlx_accel_transaction *transaction);

void mlx_accel_trans_recv(void *cb_arg, struct mlx_accel_core_dma_buf *buf);

#endif /* __MLX_ACCEL_CORE_TRANS_H__ */
