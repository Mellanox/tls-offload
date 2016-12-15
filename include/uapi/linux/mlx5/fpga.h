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

#ifndef MLX5_FPGA_H
#define MLX5_FPGA_H

enum mlx_accel_access_type {
	MLX_ACCEL_ACCESS_TYPE_I2C = 0x0,
	MLX_ACCEL_ACCESS_TYPE_RDMA,
	MLX_ACCEL_ACCESS_TYPE_DONTCARE,
	MLX_ACCEL_ACCESS_TYPE_MAX = MLX_ACCEL_ACCESS_TYPE_DONTCARE,
};

enum mlx_accel_fpga_image {
	MLX_ACCEL_IMAGE_USER = 0x0,
	MLX_ACCEL_IMAGE_FACTORY,
	MLX_ACCEL_IMAGE_MAX = MLX_ACCEL_IMAGE_FACTORY,
};

enum mlx_accel_fpga_status {
	MLX_ACCEL_FPGA_STATUS_SUCCESS = 0,
	MLX_ACCEL_FPGA_STATUS_FAILURE = 1,
	MLX_ACCEL_FPGA_STATUS_IN_PROGRESS = 2,
	MLX_ACCEL_FPGA_STATUS_NONE = 0xFFFF,
};

#endif /* MLX5_FPGA_H */
