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

#include <linux/errno.h>
#include <linux/err.h>
#include <rdma/ib_verbs.h>

#include "accel_core.h"

extern struct list_head mlx_accel_core_devices;
extern struct list_head mlx_accel_core_clients;
extern struct mutex mlx_accel_core_mutex;

void mlx_accel_core_client_register(struct mlx_accel_core_client *client)
{
	struct mlx_accel_core_device *accel_device;

	pr_info("mlx_accel_core_client_register called for %s\n", client->name);

	mutex_lock(&mlx_accel_core_mutex);

	list_for_each_entry(accel_device, &mlx_accel_core_devices, list) {
		/*
		 * TODO: Add a check of client properties against the
		 * device properties
		 */
		if (!mlx_add_accel_client_context(accel_device, client))
			client->add(accel_device);
	}
	list_add_tail(&client->list, &mlx_accel_core_clients);

	mutex_unlock(&mlx_accel_core_mutex);
}
EXPORT_SYMBOL(mlx_accel_core_client_register);

void mlx_accel_core_client_unregister(struct mlx_accel_core_client *client)
{
	struct mlx_accel_core_client *curr_client, *tmp;
	struct mlx_accel_core_device *accel_device;
	struct mlx_accel_client_data *context, *tmp_context;

	pr_info("mlx_accel_core_client_unregister called for %s\n",
		client->name);

	mutex_lock(&mlx_accel_core_mutex);

	list_for_each_entry(accel_device, &mlx_accel_core_devices, list) {
		/*
		 * TODO: Add a check of client properties against the
		 * device properties
		 */
		list_for_each_entry_safe(context, tmp_context,
					 &accel_device->client_data_list,
					 list) {
			if (context->client == client) {
				client->remove(accel_device);
				list_del(&context->list);
				kfree(context);
				break;
			}
		}
	}

	list_for_each_entry_safe(curr_client, tmp,
				 &mlx_accel_core_clients, list) {
		if (curr_client == client) {
			list_del(&client->list);
			break;
		}
	}
	mutex_unlock(&mlx_accel_core_mutex);
}
EXPORT_SYMBOL(mlx_accel_core_client_unregister);

struct mlx_accel_core_conn *
mlx_accel_core_conn_create(struct mlx_accel_core_device *accel_device,
		struct mlx_accel_core_conn_init_attr *conn_init_attr)
{
	struct mlx_accel_core_conn *conn = NULL;
	void *rc;

	pr_info("mlx_accel_core_conn_create called for %s\n",
		accel_device->name);

	conn = kzalloc(sizeof(*conn), GFP_KERNEL);
	if (!conn) {
		rc = ERR_PTR(-ENOMEM);
		goto err;
	}

	if (!conn_init_attr->recv_cb) {
		rc = ERR_PTR(-EINVAL);
		goto err;
	}

	conn->accel_device = accel_device;
	/*
	 * [AY]: TODO, for now we support only port 1 since netwon is CX4 which
	 * have rdma device per port. That mean simulator will need to run also
	 * on CX4 and Liran approved.
	 */
	conn->port_num = 1;

	atomic_set(&conn->pending_sends, 0);
	atomic_set(&conn->pending_recvs, 0);

	INIT_LIST_HEAD(&conn->pending_msgs);
	spin_lock_init(&conn->pending_lock);

	conn->recv_cb = conn_init_attr->recv_cb;
	conn->cb_arg = conn_init_attr->cb_arg;

	rc = ERR_PTR(mlx_accel_core_rdma_create_res(conn,
			conn_init_attr->tx_size, conn_init_attr->rx_size));
	if (IS_ERR(rc))
		goto err;

	return conn;
err:
	kfree(conn);
	return rc;
}
EXPORT_SYMBOL(mlx_accel_core_conn_create);

void mlx_accel_core_conn_destroy(struct mlx_accel_core_conn *conn)
{
	pr_info("mlx_accel_core_conn_destroy called for %s\n",
			conn->accel_device->name);

	mlx_accel_core_rdma_destroy_res(conn);

	kfree(conn);
}
EXPORT_SYMBOL(mlx_accel_core_conn_destroy);

int mlx_accel_core_connect(struct mlx_accel_core_conn *conn)
{
	pr_info("mlx_accel_core_connect called for %s\n",
			conn->accel_device->name);

	return mlx_accel_core_rdma_connect(conn);
}
EXPORT_SYMBOL(mlx_accel_core_connect);

/* [BP]: TODO - add a return value and another argument @retry.
 * The return value will return failure only if the post_send call failed.
 * The argument @retry, is a boolean telling whether the functing could return
 * a failure. If @retry != 0 then the function should add a pending message if
 * post_send fails. (@retry is required for the TLS module) */
void mlx_accel_core_sendmsg(struct mlx_accel_core_conn *conn,
		struct mlx_accel_core_dma_buf *buf)
{
	unsigned long flags;

	/* TODO: see if the list_empty without lock is safe here */
	if (!list_empty(&conn->pending_msgs) ||
			mlx_accel_core_rdma_post_send(conn, buf)) {
		spin_lock_irqsave(&conn->pending_lock, flags);
		if (list_empty(&conn->pending_msgs)) {
			mlx_accel_core_rdma_post_send(conn, buf);
			goto unlock;
		}
		list_add_tail(&buf->list, &conn->pending_msgs);
unlock:
		spin_unlock_irqrestore(&conn->pending_lock, flags);
	}
}
EXPORT_SYMBOL(mlx_accel_core_sendmsg);

u64 mlx_accel_core_ddr_size_get(struct mlx_accel_core_device *dev)
{
	return 0x400000000ULL;
}
EXPORT_SYMBOL(mlx_accel_core_ddr_size_get);

u64 mlx_accel_core_ddr_base_get(struct mlx_accel_core_device *dev)
{
	return 0x400000000ULL;
}
EXPORT_SYMBOL(mlx_accel_core_ddr_base_get);

int mlx_accel_core_mem_read(struct mlx_accel_core_device *dev,
			    size_t size, u64 addr, void *buf,
			    enum mlx_accel_access_type access_type)
{
	/* [AY]: TODO: In future add RDMA DDR access */
	if (access_type == MLX_ACCEL_ACCESS_TYPE_RDMA)
		return -EACCES;

	pr_debug("Reading %lu bytes at 0x%llx using %d\n", size, addr,
		 access_type);
	/* i2c access */
	mlx_accel_read_i2c(dev->hw_dev, size, addr, buf);
	return size;
}
EXPORT_SYMBOL(mlx_accel_core_mem_read);

int mlx_accel_core_mem_write(struct mlx_accel_core_device *dev,
			     size_t size, u64 addr, void *buf,
			     enum mlx_accel_access_type access_type)
{
	/* [AY]: TODO: In future add RDMA DDR access */
	if (access_type == MLX_ACCEL_ACCESS_TYPE_RDMA)
		return -EACCES;

	pr_debug("Writing %lu bytes at 0x%llx using %d\n", size, addr,
		 access_type);
	/* i2c access */
	mlx_accel_write_i2c(dev->hw_dev, size, addr, buf);
	return size;
}
EXPORT_SYMBOL(mlx_accel_core_mem_write);

void mlx_accel_core_client_data_set(struct mlx_accel_core_device *accel_device,
				    struct mlx_accel_core_client *client,
				    void *data)
{
	struct mlx_accel_client_data *context;

	list_for_each_entry(context, &accel_device->client_data_list, list)
		if (context->client == client) {
			context->data = data;
			return;
		}

	pr_warn("No client context found for %s/%s\n",
		accel_device->name, client->name);
}
EXPORT_SYMBOL(mlx_accel_core_client_data_set);

void *mlx_accel_core_client_data_get(struct mlx_accel_core_device *accel_device,
				     struct mlx_accel_core_client *client)
{
	struct mlx_accel_client_data *context;
	void *ret = NULL;

	list_for_each_entry(context, &accel_device->client_data_list, list)
		if (context->client == client) {
			ret = context->data;
			goto out;
		}
	pr_warn("No client context found for %s/%s\n",
		accel_device->name, client->name);

out:
	return ret;
}
EXPORT_SYMBOL(mlx_accel_core_client_data_get);

struct kobject *mlx_accel_core_kobj(struct mlx_accel_core_device *device)
{
	/* TODO: return port 0 as parent sysfs node, instead of "ports" node? */
	return device->ib_dev->ports_parent;
}
EXPORT_SYMBOL(mlx_accel_core_kobj);
