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

#ifndef MLX5_IB_DRIVER_H
#define MLX5_IB_DRIVER_H

#include <rdma/ib_verbs.h>

bool mlx5_ib_is_gid_reserved(struct ib_device *ib_dev, u8 port, int index);
int mlx5_ib_reserved_gid_add(struct ib_device *ib_dev, u8 port,
			     enum ib_gid_type gid_type, union ib_gid *gid,
			     u8 *mac, bool vlan, u16 vlan_id, int *gid_index);
void mlx5_ib_reserved_gid_del(struct ib_device *ib_dev, u8 port, int gid_index);
struct mlx5_core_dev *mlx5_get_mdev_from_ibdev(struct ib_device *ibdev);

#endif /* MLX5_IB_DRIVER_H */
