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

#ifndef MLX_ACCEL_SDK_H
#define MLX_ACCEL_SDK_H

#include <rdma/ib_verbs.h>
#include <linux/mlx5/driver.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/dma-direction.h>
#include <linux/kobject.h>
#include <uapi/linux/mlx5/fpga.h>

#define MLX_CLIENT_NAME_MAX			64
#define MLX_ACCEL_DEVICE_NAME_MAX	(MLX5_MAX_NAME_LEN + IB_DEVICE_NAME_MAX)

struct mlx_accel_core_conn;

/* represents an accelerated device */
struct mlx_accel_core_device {
	struct mlx5_core_dev *hw_dev;
	struct ib_device *ib_dev;
	char name[MLX_ACCEL_DEVICE_NAME_MAX];
	u8 port;
	struct mutex mutex; /* Protects state transitions */
	enum mlx_accel_fpga_status state;
	enum mlx_accel_fpga_image last_admin_image;
	enum mlx_accel_fpga_image last_oper_image;

	struct list_head list;
	struct list_head client_connections;
	struct list_head client_data_list;
	struct mlx_accel_core_conn *core_conn;
	struct kobject *class_kobj;
	struct kobject core_kobj;

	/* Transactions state */
	struct mlx_accel_trans_device_state *trans;

	/* Parameters for QPs */
	struct ib_pd *pd;
	u16 pkey_index;
};

struct mlx_accel_core_client {
	/* Informs the client that a core device was created.
	 * The device is not yet operational at this stage
	 * This callback is optional
	 */
	void (*create)(struct mlx_accel_core_device *);
	/* Informs the client that a core device is ready and operational.
	 * Any SBU-specific initialization should happen at this stage
	 * @return 0 on success, nonzero error value otherwise
	 */
	int  (*add)(struct mlx_accel_core_device *);
	/* Informs the client that a core device is not operational anymore.
	 * SBU-specific cleanup should happen at this stage
	 * This callback is called once for every successful call to add()
	 */
	void (*remove)(struct mlx_accel_core_device *);
	/* Informs the client that a core device is being destroyed.
	 * The device is not operational at this stage
	 */
	void (*destroy)(struct mlx_accel_core_device *);

	char name[MLX_CLIENT_NAME_MAX];

	struct list_head list;
};

struct mlx_accel_core_dma_buf {
	struct list_head list;
	void (*complete)(struct mlx_accel_core_conn *conn,
			 struct mlx_accel_core_dma_buf *buf, struct ib_wc *wc);
	/* Payload */
	void *data;
	size_t data_size;
	/* Optional second payload */
	void *more;
	size_t more_size;
	/* Private members */
	u64 data_dma_addr;
	u64 more_dma_addr;
	enum dma_data_direction dma_dir;
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

	atomic_t inflight_sends;
	atomic_t pending_recvs;

	/* [BP]: TODO - Why not use RCU list? */
	struct list_head pending_msgs;
	spinlock_t pending_lock;

	void (*recv_cb)(void *cb_arg, struct mlx_accel_core_dma_buf *buf);
	void *cb_arg;

	struct completion exit_completion;
	int exiting;

	struct list_head list;

	/* Parameters for the QP */
	struct ib_cq *cq;
	struct ib_qp *qp;

	struct mlx5_fpga_qpc fpga_qpc;
	int sgid_index;
	u32 fpga_qpn;
};

void mlx_accel_core_client_register(struct mlx_accel_core_client *client);
void mlx_accel_core_client_unregister(struct mlx_accel_core_client *client);
int mlx_accel_core_client_ops_register(struct mlx_accel_core_device *adev,
				       struct mlx5_accel_ops *ops);
void mlx_accel_core_client_ops_unregister(struct mlx_accel_core_device *adev);
int mlx_accel_core_device_reload(struct mlx_accel_core_device *accel_device,
				 enum mlx_accel_fpga_image image);
int mlx_accel_core_flash_select(struct mlx_accel_core_device *accel_device,
				enum mlx_accel_fpga_image image);

struct mlx_accel_core_conn *
mlx_accel_core_conn_create(struct mlx_accel_core_device *accel_device,
			   struct mlx_accel_core_conn_init_attr *attr);
void mlx_accel_core_conn_destroy(struct mlx_accel_core_conn *conn);

int mlx_accel_core_connect(struct mlx_accel_core_conn *conn);

int mlx_accel_core_sendmsg(struct mlx_accel_core_conn *conn,
			   struct mlx_accel_core_dma_buf *buf);
ssize_t mlx_accel_counters_sysfs_store(struct mlx_accel_core_conn *conn,
				       const char *buf, size_t size);
ssize_t mlx_accel_counters_sysfs_show(struct mlx_accel_core_conn *conn,
				      char *buf);

u64 mlx_accel_core_ddr_size_get(struct mlx_accel_core_device *dev);
u64 mlx_accel_core_ddr_base_get(struct mlx_accel_core_device *dev);
int mlx_accel_core_mem_read(struct mlx_accel_core_device *dev,
			    size_t size, u64 addr, void *buf,
			    enum mlx_accel_access_type access_type);
int mlx_accel_core_mem_write(struct mlx_accel_core_device *dev,
			     size_t size, u64 addr, void *buf,
			     enum mlx_accel_access_type access_type);

void mlx_accel_core_client_data_set(struct mlx_accel_core_device *accel_device,
				    struct mlx_accel_core_client *client,
				    void *data);
void *mlx_accel_core_client_data_get(struct mlx_accel_core_device *accel_device,
				     struct mlx_accel_core_client *client);

struct kobject *mlx_accel_core_kobj(struct mlx_accel_core_device *accel_device);
int mlx_accel_get_sbu_caps(struct mlx_accel_core_device *dev, int size,
			   void *buf);
#endif /* MLX_ACCEL_SDK_H */
