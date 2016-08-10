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

#ifndef __IPSEC_H__
#define __IPSEC_H__

/* #define MLX_IPSEC_SADB_RDMA */

#include <linux/types.h>
#include <linux/kobject.h>
#include <linux/kfifo.h>
#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/hashtable.h>
#include <linux/mlx5/en_driver.h>
#include <linux/mlx5/device.h>
#include <net/sock.h>
#include <net/inet_common.h>
#include <net/xfrm.h>

#include "../core/accel_core_sdk.h"
#include "ipsec_cmds.h"

#define DRIVER_NAME		"mlx_ipsec"
#define DRIVER_VERSION	"0.1"
#define DRIVER_RELDATE	"January 2016"

#define MLX_IPSEC_DEVICE_NAME					"mlx_ipsec"
/* TODO: Consider moving this to include/uapi/linux/if_ether.h */
#define MLX_IPSEC_PET_ETHERTYPE					(0x8CE4)

#define MLX_IPSEC_SA_HASH_TABLE_BITS			10
#define MLX_SA_HW2SW_FIFO_SIZE				8

struct mlx_ipsec_sa_entry {
	unsigned int sw_sa_id;
	unsigned int hw_sa_id;	/* unused */
	struct hlist_node hlist;
	struct xfrm_state *x;
	enum fpga_add_sa_status status;
	struct mlx_ipsec_dev *dev;
};

struct mlx_ipsec_dev {
	struct kobject kobj;
	struct list_head accel_dev_list;
	struct mlx_accel_core_device *accel_device;
	struct mlx_accel_core_conn *conn;
	/* [BP]: TODO - move this to mlx_accel_core_ctx */
	struct net_device *netdev;
	DECLARE_KFIFO(fifo_sa_cmds, struct mlx_ipsec_sa_entry *,
			MLX_SA_HW2SW_FIFO_SIZE);
	DECLARE_HASHTABLE(sw_sa_id2xfrm_state_table,
			MLX_IPSEC_SA_HASH_TABLE_BITS);
	spinlock_t fifo_sa_cmds_lock;
	spinlock_t sw_sa_id2xfrm_state_lock;
	atomic_t next_sw_sa_id;
	wait_queue_head_t wq;
	u32 ipsec_caps[MLX5_ST_SZ_DW(ipsec_extended_cap)];
};

void mlx_ipsec_dev_release(struct kobject *kobj);

int mlx_ipsec_netdev_event(struct notifier_block *this,
		unsigned long event, void *ptr);

int mlx_ipsec_add_one(struct mlx_accel_core_device *accel_device);
void mlx_ipsec_remove_one(struct mlx_accel_core_device *accel_device);

int mlx_xfrm_offload_input(struct xfrm_state *x, struct sk_buff **skb);
int mlx_xfrm_offload_output(struct xfrm_state *x, struct sk_buff **skb);

struct mlx_ipsec_dev *mlx_ipsec_find_dev_by_netdev(struct net_device *netdev);
int mlx_ipsec_get_count(struct net_device *netdev);
int mlx_ipsec_get_strings(struct net_device *netdev, uint8_t *data);
int mlx_ipsec_get_stats(struct net_device *netdev, u64 *data);

#endif	/* __IPSEC_H__ */
