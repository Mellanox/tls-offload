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

#include <linux/mlx5/driver.h>
#include <linux/mlx5/cmd.h>
#include "mlx5_core.h"

int mlx5_fpga_access_reg(struct mlx5_core_dev *dev, u8 size, u64 addr,
			 u8 *buf, bool write)
{
#if IS_ENABLED(CONFIG_MLX5_CORE_FPGA_QP_SIM)
	return -EPERM;
#else
	u32 in[MLX5_ST_SZ_DW(fpga_access_reg) + MLX5_FPGA_ACCESS_REG_SIZE_MAX];
	u32 out[MLX5_ST_SZ_DW(fpga_access_reg) + MLX5_FPGA_ACCESS_REG_SIZE_MAX];
	int err;

	if (size & 3)
		return -EINVAL;
	if (addr & 3)
		return -EINVAL;
	if (size > MLX5_FPGA_ACCESS_REG_SIZE_MAX)
		return -EINVAL;

	memset(in, 0, sizeof(in));
	MLX5_SET(fpga_access_reg, in, size, size);
	MLX5_SET(fpga_access_reg, in, address_h, addr >> 32);
	MLX5_SET(fpga_access_reg, in, address_l, addr & 0xFFFFFFFF);
	if (write)
		memcpy(MLX5_ADDR_OF(fpga_access_reg, in, data), buf, size);

	err = mlx5_core_access_reg(dev, in, sizeof(in), out, sizeof(out),
				   MLX5_REG_FPGA_ACCESS_REG, 0, write);
	if (err)
		return err;

	if (!write)
		memcpy(buf, MLX5_ADDR_OF(fpga_access_reg, out, data), size);

	return 0;
#endif
}
EXPORT_SYMBOL_GPL(mlx5_fpga_access_reg);

int mlx5_fpga_caps(struct mlx5_core_dev *dev, u32 *caps)
{
#if IS_ENABLED(CONFIG_MLX5_CORE_FPGA_QP_SIM)
	return -EPERM;
#else
	int err;
	u32 in[MLX5_ST_SZ_DW(fpga_cap)];
	u32 out[MLX5_ST_SZ_DW(fpga_cap)];

	memset(in, 0, sizeof(in));
	err = mlx5_core_access_reg(dev, in, sizeof(in), out, sizeof(out),
				   MLX5_REG_FPGA_CAP, 0, 0);
	if (err)
		return err;

	memcpy(caps, out, sizeof(out));
#ifdef DEBUG
	print_hex_dump_bytes("FPGA caps ", DUMP_PREFIX_OFFSET, out,
			     sizeof(out));
#endif
	return 0;
#endif
}
EXPORT_SYMBOL_GPL(mlx5_fpga_caps);

int mlx5_fpga_sbu_caps(struct mlx5_core_dev *dev, void *caps, int size)
{
#if IS_ENABLED(CONFIG_MLX5_CORE_FPGA_QP_SIM)
	return -EPERM;
#else
	u64 addr = MLX5_CAP64_FPGA(dev, sandbox_extended_caps_addr);
	int cap_size = MLX5_CAP_FPGA(dev, sandbox_extended_caps_len);
	int ret = 0;
	int read;

	if (cap_size > size) {
		mlx5_core_warn(dev, "Not enough buffer %u for FPGA SBU caps %u",
			       size, cap_size);
		return -EINVAL;
	}

	while (cap_size > 0) {
		read = cap_size;
		if (read > MLX5_FPGA_ACCESS_REG_SIZE_MAX)
			read = MLX5_FPGA_ACCESS_REG_SIZE_MAX;

		ret = mlx5_fpga_access_reg(dev, cap_size, addr, caps, false);
		if (ret) {
			mlx5_core_warn(dev, "Error reading FPGA SBU caps");
			return ret;
		}

		cap_size -= read;
		addr += read;
		caps += read;
	}

	return ret;
#endif
}
EXPORT_SYMBOL(mlx5_fpga_sbu_caps);

static int mlx5_fpga_ctrl_write(struct mlx5_core_dev *dev, u8 op,
				enum mlx_accel_fpga_image image)
{
#if IS_ENABLED(CONFIG_MLX5_CORE_FPGA_QP_SIM)
	return -EPERM;
#else
	u32 in[MLX5_ST_SZ_DW(fpga_ctrl)];
	u32 out[MLX5_ST_SZ_DW(fpga_ctrl)];

	memset(in, 0, sizeof(in));
	MLX5_SET(fpga_ctrl, in, operation, op);
	MLX5_SET(fpga_ctrl, in, image_select_admin, image);

	return mlx5_core_access_reg(dev, in, sizeof(in), out, sizeof(out),
				    MLX5_REG_FPGA_CTRL, 0, true);
#endif
}

int mlx5_fpga_load(struct mlx5_core_dev *dev, enum mlx_accel_fpga_image image)
{
	return mlx5_fpga_ctrl_write(dev, MLX5_FPGA_CTRL_OP_LOAD, image);
}
EXPORT_SYMBOL(mlx5_fpga_load);

int mlx5_fpga_ctrl_op(struct mlx5_core_dev *dev, u8 op)
{
	return mlx5_fpga_ctrl_write(dev, op, 0);
}
EXPORT_SYMBOL(mlx5_fpga_ctrl_op);

int mlx5_fpga_image_select(struct mlx5_core_dev *dev,
			   enum mlx_accel_fpga_image image)
{
	return mlx5_fpga_ctrl_write(dev, MLX5_FPGA_CTRL_OP_IMAGE_SEL, image);
}
EXPORT_SYMBOL(mlx5_fpga_image_select);

int mlx5_fpga_query(struct mlx5_core_dev *dev,
		    enum mlx_accel_fpga_status *status,
		    enum mlx_accel_fpga_image *admin_image,
		    enum mlx_accel_fpga_image *oper_image)
{
#if IS_ENABLED(CONFIG_MLX5_CORE_FPGA_QP_SIM)
	return -EPERM;
#else
	u32 in[MLX5_ST_SZ_DW(fpga_ctrl)];
	u32 out[MLX5_ST_SZ_DW(fpga_ctrl)];
	int err;

	memset(in, 0, sizeof(in));
	err = mlx5_core_access_reg(dev, in, sizeof(in), out, sizeof(out),
				   MLX5_REG_FPGA_CTRL, 0, false);
	if (err)
		goto out;

	if (status)
		*status = MLX5_GET(fpga_ctrl, out, status);
	if (admin_image)
		*admin_image = MLX5_GET(fpga_ctrl, out, image_select_admin);
	if (oper_image)
		*oper_image = MLX5_GET(fpga_ctrl, out, image_select_oper);

out:
	return err;
#endif
}
EXPORT_SYMBOL(mlx5_fpga_query);
