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

#include <linux/etherdevice.h>
#include <linux/mlx5/device.h>
#include <linux/mlx5/driver.h>
#include <rdma/ib_mad.h>

#include "fpga.h"
#include "accel_core.h"

int mlx_accel_read_i2c(struct mlx_accel_core_device *adev,
		       size_t size, u64 addr, u8 *buf)
{
	u8 actual_size;
	size_t bytes_done = 0;
	size_t max_size = MLX5_FPGA_ACCESS_REG_SIZE_MAX;
	int rc;

	while (bytes_done < size) {
		actual_size = min(max_size, (size - bytes_done));

		rc = mlx5_fpga_access_reg(adev->hw_dev, actual_size,
					  addr + bytes_done,
					  buf + bytes_done, false);
		if (rc) {
			mlx_accel_err(adev, "Failed to read FPGA crspace\n");
			return rc;
		}

		bytes_done += actual_size;
	}

	return 0;
}

int mlx_accel_write_i2c(struct mlx_accel_core_device *adev,
			size_t size, u64 addr, u8 *buf)
{
	u8 actual_size;
	size_t bytes_done = 0;
	size_t max_size = MLX5_FPGA_ACCESS_REG_SIZE_MAX;
	int rc;

	while (bytes_done < size) {
		actual_size = min(max_size, (size - bytes_done));

		rc = mlx5_fpga_access_reg(adev->hw_dev, actual_size,
					  addr + bytes_done,
					  buf + bytes_done, true);
		if (rc) {
			mlx_accel_err(adev, "Failed to write FPGA crspace\n");
			return rc;
		}

		bytes_done += actual_size;
	}

	return 0;
}
