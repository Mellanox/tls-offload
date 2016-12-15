/*
 * Copyright (c) 2013-2015, Mellanox Technologies. All rights reserved.
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
 */

#ifndef MLX5_ACCEL_FPGA_H
#define MLX5_ACCEL_FPGA_H

#include <linux/mlx5/driver.h>
#include <uapi/linux/mlx5/fpga.h>

int mlx5_fpga_shell_counters(struct mlx5_core_dev *dev, bool clear,
			     struct mlx5_fpga_shell_counters *data);
int mlx5_fpga_create_qp(struct mlx5_core_dev *dev,
			struct mlx5_fpga_qpc *fpga_qpc, u32 *fpga_qpn);
int mlx5_fpga_modify_qp(struct mlx5_core_dev *dev, u32 fpga_qpn,
			enum mlx5_fpga_qpc_field_select fields,
			struct mlx5_fpga_qpc *fpga_qpc);
int mlx5_fpga_query_qp(struct mlx5_core_dev *dev, u32 fpga_qpn,
		       struct mlx5_fpga_qpc *fpga_qpc);
int mlx5_fpga_query_qp_counters(struct mlx5_core_dev *dev, u32 fpga_qpn,
				bool clear, struct mlx5_fpga_qp_counters *data);
int mlx5_fpga_destroy_qp(struct mlx5_core_dev *dev, u32 fpga_qpn);

#endif /* MLX5_ACCEL_FPGA_H */
