/*
 * Copyright (c) 2015-2017 Mellanox Technologies. All rights reserved.
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
#ifndef __TLS_H__
#define __TLS_H__

#include <linux/types.h>
#include <linux/kobject.h>
#include <linux/kfifo.h>
#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/hashtable.h>
#include <net/sock.h>
#include <net/inet_common.h>
#include <net/tls.h>
#include <linux/mlx5/accel_sdk.h>

#include "tls_cmds.h"

#define DRIVER_NAME	"mlx_tls"
#define DRIVER_VERSION	"0.1"
#define DRIVER_RELDATE	"January 2016"

#define MLX_TLS_DEVICE_NAME					"mlx_tls"
/* TODO: Consider moving this to include/uapi/linux/if_ether.h */

struct send_pet_content {
	/* The next field is meaningful only for sync packets with LSO
	 * enabled (by the syndrome field))
	 */
	__be16 first_seq;	/* LSBs of the first TCP seq in the packet */
	unsigned char sid[3];
} __packed;

/*TODO: move this to HW/cmds header files when added*/
struct pet {
	unsigned char syndrome;
	union {
		unsigned char raw[5];
		/* from host to FPGA */
		struct send_pet_content send;
	} __packed content;
	/* packet type ID field	*/
	__be16 ethertype;
} __packed;

struct mlx_tls_dev {
	struct kobject kobj;
	struct list_head accel_dev_list;
	struct mlx_accel_core_device *accel_device;
	struct mlx_accel_core_conn *conn;
	struct net_device *netdev;
	struct ida swid_ida;
};

struct mlx_tls_offload_context {
	struct tls_offload_context context;
	struct list_head tls_del_list;
	struct net_device *netdev;
	__be32 swid;
};

int mlx_tls_netdev_event(struct notifier_block *this,
			 unsigned long event, void *ptr);

int mlx_tls_add_one(struct mlx_accel_core_device *accel_device);
void mlx_tls_remove_one(struct mlx_accel_core_device *accel_device);

struct mlx_tls_dev *mlx_tls_find_dev_by_netdev(struct net_device *netdev);

#endif	/* __TLS_H__ */
