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

#ifndef __MLX_ACCEL_CORE_SDK_H__
#define __MLX_ACCEL_CORE_SDK_H__

#include <rdma/ib_verbs.h>
#include <linux/mlx5/driver.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/dma-direction.h>
#include <linux/kobject.h>


#define MLX_CLIENT_NAME_MAX			64
#define MLX_ACCEL_DEVICE_NAME_MAX	(MLX5_MAX_NAME_LEN + IB_DEVICE_NAME_MAX)

struct mlx_accel_core_conn;

/* represents an accelerated ib_device */
struct mlx_accel_core_device {
	struct mlx5_core_dev *hw_dev;
	struct ib_device *ib_dev;
	char name[MLX_ACCEL_DEVICE_NAME_MAX];
	unsigned int properties; /* accelerator properties the device support */

	struct list_head connections;

	struct list_head list;
};

struct mlx_accel_core_client {
	void (*add)    (struct mlx_accel_core_device *);
	void (*remove) (struct mlx_accel_core_device *);

	char name[MLX_CLIENT_NAME_MAX];
	unsigned int properties; /* accelerator properties the client support */

	struct list_head list;
};

struct mlx_accel_core_dma_buf {
	struct list_head list;
	u64 dma_addr;
	enum dma_data_direction dma_dir;
	size_t data_size;
	size_t offset;
	char data[];
};

struct mlx_accel_core_conn_init_attr {
	unsigned int tx_size;
	unsigned int rx_size;
	void (*recv_cb)(void *cb_arg, struct mlx_accel_core_dma_buf *buf);
	void *cb_arg;
};

struct mlx_accel_core_conn {
	struct mlx_accel_core_device *accel_device;
	u8 port_num;

	atomic_t pending_sends;
	atomic_t pending_recvs;

	struct list_head pending_msgs;
	spinlock_t pending_lock;

	void (*recv_cb)(void *cb_arg, struct mlx_accel_core_dma_buf *buf);
	void *cb_arg;

	struct completion exit_completion;
	int exiting;

	struct ib_pd *pd;
	struct ib_mr *mr;
	struct ib_cq *cq;
	struct ib_qp *qp;
	union ib_gid gid;
	u16 pkey;			/* TODO */
	u8 sl;				/* TODO */

	u32 dqpn;			/* TODO */
	union ib_gid dgid;	/* TODO */

	struct list_head list;
};


void mlx_accel_core_register_client(struct mlx_accel_core_client *client);
void mlx_accel_core_unregister_client(struct mlx_accel_core_client *client);

struct mlx_accel_core_conn *
mlx_accel_core_conn_create(struct mlx_accel_core_device *accel_device,
		struct mlx_accel_core_conn_init_attr *conn_init_attr);
void mlx_accel_core_conn_destroy(struct mlx_accel_core_conn *conn);

int mlx_accel_core_connect(struct mlx_accel_core_conn *conn);

void mlx_accel_core_sendmsg(struct mlx_accel_core_conn *conn,
		struct mlx_accel_core_dma_buf *buf);


struct ib_port {
	struct kobject         kobj;
	struct ib_device      *ibdev;
	struct attribute_group gid_group;
	struct attribute_group pkey_group;
	u8                     port_num;
};

static inline struct kobject *
mlx_accel_core_get_kobject_parent(struct mlx_accel_core_conn *conn)
{
	struct kobject *p = NULL, *result = NULL;

	list_for_each_entry(p, &conn->accel_device->ib_dev->port_list, entry) {
		struct ib_port *port = container_of(p, struct ib_port, kobj);
		if (port->port_num == 0) {
			result = &port->kobj;
			break;
		}
	}

	return result;
}

#endif /* __MLX_ACCEL_CORE_SDK_H__ */
