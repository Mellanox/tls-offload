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

#ifndef MLX5_EN_DRIVER_H
#define MLX5_EN_DRIVER_H

#include <linux/mlx5/driver.h>
#include <uapi/linux/mlx5/fpga.h>

struct mlx5e_swp_info {
	u8 outer_l4_ofs;
	u8 outer_l3_ofs;
	u8 inner_l4_ofs;
	u8 inner_l3_ofs;
	u8 swp_flags;
};

struct mlx5e_accel_client_ops {
	struct sk_buff  *(*rx_handler)(struct sk_buff *skb, u8 *pet, u8 petlen);
	struct sk_buff  *(*tx_handler)(struct sk_buff *skb,
				       struct mlx5e_swp_info *swp);
	netdev_features_t (*feature_chk)(struct sk_buff *skb,
					 struct net_device *netdev,
					 netdev_features_t features,
					 bool *done);
	u16 (*mtu_handler)(u16 mtu, bool hw_sw_);
	int (*get_count)(struct net_device *netdev);
	int (*get_strings)(struct net_device *netdev, uint8_t *data);
	int (*get_stats)(struct net_device *netdev, u64 *data);
};

int
mlx5e_register_accel_ops(struct net_device *netdev,
			struct mlx5e_accel_client_ops *client_ops);
void mlx5e_unregister_accel_ops(struct net_device *netdev);
#endif /* MLX5_EN_DRIVER_H */
