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

static netdev_features_t mlx5_accel_feature_chk(struct sk_buff *skb,
						struct net_device *netdev,
						netdev_features_t features,
						bool *done)
{
	return features;
}

static struct sk_buff *mlx5_accel_tx_handler(struct sk_buff *skb,
					     struct mlx5_swp_info *swp)
{
	return skb;
}

static struct sk_buff *mlx5_accel_rx_handler(struct sk_buff *skb, u8 *pet,
					     u8 petlen)
{
	return skb;
}

static int mlx5_accel_get_count(struct net_device *netdev)
{
	return 0;
}

static int mlx5_accel_get_strings(struct net_device *netdev, uint8_t *data)
{
	return 0;
}

static int mlx5_accel_get_stats(struct net_device *netdev, u64 *data)
{
	return 0;
}

static struct mlx5_accel_ops accel_ops_default = {
	.rx_handler = mlx5_accel_rx_handler,
	.tx_handler = mlx5_accel_tx_handler,
	.feature_chk = mlx5_accel_feature_chk,
	.get_count = mlx5_accel_get_count,
	.get_strings = mlx5_accel_get_strings,
	.get_stats = mlx5_accel_get_stats,
	.mtu_extra = 0,
	.features = 0,
};

struct mlx5_accel_ops *mlx5_accel_get(struct mlx5_core_dev *dev)
{
	return rcu_dereference(dev->accel_ops);
}
EXPORT_SYMBOL(mlx5_accel_get);

int mlx5_accel_register(struct mlx5_core_dev *dev,
			struct mlx5_accel_ops *ops)
{
	WARN_ON(!ops->tx_handler || !ops->rx_handler);
	WARN_ON(!ops->get_count || !ops->get_strings || !ops->get_stats);
	WARN_ON(!ops->feature_chk);

	if (rcu_access_pointer(dev->accel_ops) != &accel_ops_default) {
		pr_err("mlx5_register_accel_ops(): Error registering accel ops over non-default pointer\n");
		return -EACCES;
	}
	rcu_assign_pointer(dev->accel_ops, ops);
	synchronize_rcu();

	dev->event(dev, MLX5_DEV_EVENT_ACCEL_CHANGE, 0);
	return 0;
}
EXPORT_SYMBOL(mlx5_accel_register);

void mlx5_accel_unregister(struct mlx5_core_dev *dev)
{
	rcu_assign_pointer(dev->accel_ops, &accel_ops_default);
	synchronize_rcu();

	dev->event(dev, MLX5_DEV_EVENT_ACCEL_CHANGE, 0);
}
EXPORT_SYMBOL(mlx5_accel_unregister);

void mlx5_accel_init(struct mlx5_core_dev *dev)
{
	rcu_assign_pointer(dev->accel_ops, &accel_ops_default);
}

void mlx5_accel_destroy(struct mlx5_core_dev *dev)
{
	struct mlx5_accel_ops *accel_ops;

	rcu_read_lock();
	accel_ops = mlx5_accel_get(dev);
	rcu_read_unlock();
	WARN_ON(accel_ops != &accel_ops_default);
}
