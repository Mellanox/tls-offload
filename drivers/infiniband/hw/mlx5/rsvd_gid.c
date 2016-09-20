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

#include <linux/mlx5_ib/driver.h>
#include "mlx5_ib.h"

#define MLX5_FPGA_MAX_NUM_QPS 2
void mlx5_ib_reserved_gid_init(struct mlx5_ib_dev *dev)
{
	int ix;
	unsigned int count = 0;

	if (MLX5_CAP_GEN(dev->mdev, fpga))
		count = MLX5_FPGA_MAX_NUM_QPS;

	if (count > MLX5_MAX_RESERVED_GIDS)
		count = MLX5_MAX_RESERVED_GIDS;

	pr_debug("Reserving %u GIDs\n", count);
	dev->reserved_gids.count = count;
	for (ix = 0; ix < count; ix++)
		dev->reserved_gids.used[ix] = false;
}

bool mlx5_ib_is_gid_reserved(struct ib_device *ib_dev, u8 port, int index)
{
	struct mlx5_ib_dev *dev = to_mdev(ib_dev);
	int table_size = dev->mdev->port_caps[port - 1].gid_table_len;

	return (index >= table_size) &&
	       (index < table_size + dev->reserved_gids.count);
}
EXPORT_SYMBOL_GPL(mlx5_ib_is_gid_reserved);

int mlx5_ib_reserved_gid_add(struct ib_device *ib_dev, u8 port,
			     enum ib_gid_type gid_type, union ib_gid *gid,
			     u8 *mac, bool vlan, u16 vlan_id, int *gid_index)
{
	struct mlx5_ib_dev *dev = to_mdev(ib_dev);
	int index = 0;
	int ret = 0;
	int empty_index;
	int table_size = dev->mdev->port_caps[port - 1].gid_table_len;

	mutex_lock(&dev->reserved_gids.mutex);
	while ((index < dev->reserved_gids.count) &&
	       dev->reserved_gids.used[index])
		index++;
	if (index >= dev->reserved_gids.count)
		ret = -ENOMEM;
	else
		dev->reserved_gids.used[index] = true;
	mutex_unlock(&dev->reserved_gids.mutex);

	if (ret)
		goto out;
	empty_index = table_size + index;
	pr_debug("Reserving GID %u\n", empty_index);

	ret = mlx5_ib_set_roce_gid(dev->mdev, empty_index, gid_type, gid,
				   mac, vlan, vlan_id);
	if (ret)
		goto out;
	*gid_index = empty_index;

out:
	return ret;
}
EXPORT_SYMBOL_GPL(mlx5_ib_reserved_gid_add);

void mlx5_ib_reserved_gid_del(struct ib_device *ib_dev, u8 port, int gid_index)
{
	struct mlx5_ib_dev *dev = to_mdev(ib_dev);
	int table_size = dev->mdev->port_caps[port - 1].gid_table_len;
	int index, ret = 0;

	if (!mlx5_ib_is_gid_reserved(ib_dev, port, gid_index)) {
		pr_warn("Not a reserved GID %u\n", gid_index);
		return;
	}

	pr_debug("Unreserving GID %u\n", gid_index);
	ret = mlx5_ib_set_roce_gid(dev->mdev, gid_index, IB_GID_TYPE_IB,
				   NULL, NULL, false, 0);
	if (ret) {
		pr_warn("Failed to delete reserved GID %u: %u\n", gid_index,
			ret);
		return;
	}

	index = gid_index - table_size;
	mutex_lock(&dev->reserved_gids.mutex);
	if (!dev->reserved_gids.used[index])
		pr_warn("Deleting an unused reserved GID %u\n", gid_index);
	dev->reserved_gids.used[index] = false;
	mutex_unlock(&dev->reserved_gids.mutex);
}
EXPORT_SYMBOL_GPL(mlx5_ib_reserved_gid_del);
