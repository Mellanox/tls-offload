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
#include <linux/mlx5/device.h>

static int mlx_accel_access_fnvcra(struct mlx5_core_dev *dev,
				   u8 size, u64 addr, u8 *buf, int write)
{
	u32 in[MLX5_ST_SZ_DW(fnvcra_reg)];
	u32 out[MLX5_ST_SZ_DW(fnvcra_reg)];
	u32 addr_high = addr >> 32;
	u32 addr_low = addr & 0xffffffff;
	int err, i;

	/* check DWORD alignment both for address and size */
	if (((size & 0x3) != 0) || ((addr_low & 0x3) != 0))
		return -EINVAL;

	memset(in, 0, sizeof(in));
	memset(out, 0, sizeof(out));

	pr_debug("FNVCRA %u bytes at 0x%llx write?%d\n", size, addr, write);

	MLX5_SET(fnvcra_reg, in, size, size);
	MLX5_SET(fnvcra_reg, in, address_63_32, addr_high);
	MLX5_SET(fnvcra_reg, in, address_31_0, addr_low);
	if (write) {
		for (i = 0; i < size; ++i)
			MLX5_SET(fnvcra_reg, in, data[i], buf[i]);
	}

	err = mlx5_core_access_reg(dev, in, sizeof(in), out, sizeof(out),
				   MLX5_REG_FNVCRA, 0, !!write);
	if (err)
		return err;

	if (!write) {
		for (i = 0; i < size; i++)
			buf[i] = MLX5_GET(fnvcra_reg, out, data[i]);
	}

	return 0;
}

int mlx_accel_read_i2c(struct mlx5_core_dev *dev,
		       size_t size, u64 addr, u8 *buf)
{
	u8 actual_size;
	size_t bytes_done = 0;
	int rc;

	while (bytes_done < size) {
		actual_size = min(MLX5_FLD_SZ_BYTES(fnvcra_reg, data),
				  (size - bytes_done));

		rc = mlx_accel_access_fnvcra(dev, actual_size,
					     addr + bytes_done,
					     buf + bytes_done, 0);
		if (rc) {
			pr_err("Failed to read FPGA crspace data for %s\n",
			       dev_name(&dev->pdev->dev));
			return rc;
		}

		bytes_done += actual_size;
	}

	return 0;
}

int mlx_accel_write_i2c(struct mlx5_core_dev *dev,
			size_t size, u64 addr, u8 *buf)
{
	u8 actual_size;
	size_t bytes_done = 0;
	int rc;

	while (bytes_done < size) {
		actual_size = min(MLX5_FLD_SZ_BYTES(fnvcra_reg, data),
				  (size - bytes_done));

		rc = mlx_accel_access_fnvcra(dev, actual_size,
					     addr + bytes_done,
					     buf + bytes_done, 1);
		if (rc) {
			pr_err("Failed to write FPGA crspace data for %s\n",
			       dev_name(&dev->pdev->dev));
			return rc;
		}

		bytes_done += actual_size;
	}

	return 0;
}

