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

#include "tools.h"
#include "tools_char.h"

struct mlx_accel_tools_dev *
mlx_accel_tools_alloc(struct mlx_accel_core_device *device)
{
	int ret;
	struct mlx_accel_tools_dev *sb_dev;

	sb_dev = kzalloc(sizeof(*sb_dev), GFP_KERNEL);
	if (!sb_dev)
		goto out;

	sb_dev->accel_device = device;
	mutex_init(&sb_dev->mutex);
	ret = mlx_accel_tools_char_add_one(sb_dev);
	if (ret)
		goto err_free;

	goto out;

err_free:
	kfree(sb_dev);
	sb_dev = NULL;

out:
	return sb_dev;
}

void mlx_accel_tools_free(struct mlx_accel_tools_dev *sb_dev)
{
	mlx_accel_tools_char_remove_one(sb_dev);
	kfree(sb_dev);
}

int mlx_accel_tools_mem_write(struct mlx_accel_tools_dev *sb_dev,
			      /*const*/ void *buf,
			      size_t count, u64 address,
			      enum mlx_accel_access_type access_type)
{
	int ret;

	ret = mutex_lock_interruptible(&sb_dev->mutex);
	if (ret)
		goto out;

	ret = mlx_accel_core_mem_write(sb_dev->accel_device, count, address,
				       buf, access_type);
	if (ret < 0) {
		pr_err("mlx_accel_tools_mem_write: Failed to write %lu bytes at address 0x%llx: %d\n",
		       count, address, ret);
		goto unlock;
	}

unlock:
	mutex_unlock(&sb_dev->mutex);

out:
	return ret;
}

int mlx_accel_tools_mem_read(struct mlx_accel_tools_dev *sb_dev, void *buf,
			     size_t count, u64 address,
			     enum mlx_accel_access_type access_type)
{
	int ret;

	ret = mutex_lock_interruptible(&sb_dev->mutex);
	if (ret)
		goto out;

	ret = mlx_accel_core_mem_read(sb_dev->accel_device, count, address, buf,
				      access_type);
	if (ret < 0) {
		pr_err("mlx_accel_tools_mem_read: Failed to read %lu bytes at address 0x%llx: %d\n",
		       count, address, ret);
		goto unlock;
	}

unlock:
	mutex_unlock(&sb_dev->mutex);

out:
	return ret;
}
