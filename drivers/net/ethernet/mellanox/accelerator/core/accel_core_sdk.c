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
#include <linux/completion.h>
#include <rdma/ib_verbs.h>

#include "accel_core.h"
#include "accel_core_xfer.h"

extern struct list_head mlx_accel_core_devices;
extern struct list_head mlx_accel_core_clients;
extern struct mutex mlx_accel_core_mutex;

void mlx_accel_core_client_register(struct mlx_accel_core_client *client)
{
	struct mlx_accel_core_device *accel_device;

	pr_info("mlx_accel_core_client_register called for %s\n", client->name);

	mutex_lock(&mlx_accel_core_mutex);

	list_for_each_entry(accel_device, &mlx_accel_core_devices, list)
		if (accel_device->core_conn)
			mlx_accel_client_context_add(accel_device, client);

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
		list_for_each_entry_safe(context, tmp_context,
					 &accel_device->client_data_list,
					 list) {
			pr_debug("Unregister client %p. context %p device %p client %p\n",
				 client, context, accel_device,
				 context->client);
			if (context->client == client) {
				client->remove(accel_device);
				mlx_accel_client_context_del(context);
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

int
mlx_accel_core_client_ops_register(struct net_device *netdev,
				   struct mlx5e_accel_client_ops *client_ops)
{
	int ret = 0;

	ret = mlx5e_register_accel_ops(netdev, client_ops);
	if (ret)
		pr_err("mlx_ipsec_add_one(): Got error while registering client_ops %d\n",
		       ret);
	return ret;
}
EXPORT_SYMBOL(mlx_accel_core_client_ops_register);

void mlx_accel_core_client_ops_unregister(struct net_device *netdev)
{
	mlx5e_unregister_accel_ops(netdev);
}
EXPORT_SYMBOL(mlx_accel_core_client_ops_unregister);

struct mlx_accel_core_conn *
mlx_accel_core_conn_create(struct mlx_accel_core_device *accel_device,
		struct mlx_accel_core_conn_init_attr *conn_init_attr)
{
	pr_info("mlx_accel_core_conn_create called for %s\n",
		accel_device->name);

	return mlx_accel_core_rdma_conn_create(accel_device,
					conn_init_attr, false);
}
EXPORT_SYMBOL(mlx_accel_core_conn_create);

void mlx_accel_core_conn_destroy(struct mlx_accel_core_conn *conn)
{
	pr_info("mlx_accel_core_conn_destroy called for %s\n",
			conn->accel_device->name);

	mlx_accel_core_rdma_conn_destroy(conn);
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

struct mem_transfer {
	struct mlx_accel_transaction t;
	struct completion comp;
	enum ib_wc_status status;
};

static void
mlx_accel_core_mem_complete(const struct mlx_accel_transaction *complete,
			    enum ib_wc_status status)
{
	struct mem_transfer *xfer;

	pr_debug("Memory transaction %p is complete with status %u\n",
		 complete, status);

	xfer = container_of(complete, struct mem_transfer, t);
	xfer->status = status;
	complete_all(&xfer->comp);
}

int mlx_accel_core_mem_transaction(struct mlx_accel_core_device *dev,
				   size_t size, u64 addr, void *buf,
				   enum mlx_accel_direction direction)
{
	int ret;
	struct mem_transfer xfer;

	if (!dev->core_conn) {
		ret = -ENOTCONN;
		goto out;
	}

	xfer.t.data = buf;
	xfer.t.size = size;
	xfer.t.addr = addr;
	xfer.t.conn = dev->core_conn;
	xfer.t.direction = direction;
	xfer.t.complete = mlx_accel_core_mem_complete;
	init_completion(&xfer.comp);
	ret = mlx_accel_xfer_exec(&xfer.t);
	if (ret) {
		pr_debug("Transaction returned value %d\n", ret);
		goto out;
	}
	ret = wait_for_completion_interruptible(&xfer.comp);
	if (ret) {
		pr_debug("Wait completed with value %d\n", ret);
		/* TODO: Cancel the transfer! */
		goto out;
	}
	if (xfer.status != 0)
		ret = -EIO;
out:
	return ret;
}

int mlx_accel_core_mem_read(struct mlx_accel_core_device *dev,
			    size_t size, u64 addr, void *buf,
			    enum mlx_accel_access_type access_type)
{
	int ret;

	if (access_type == MLX_ACCEL_ACCESS_TYPE_DONTCARE)
		access_type = dev->core_conn ? MLX_ACCEL_ACCESS_TYPE_RDMA :
			      MLX_ACCEL_ACCESS_TYPE_I2C;

	pr_debug("**** Reading %lu bytes at 0x%llx using %s\n", size, addr,
		 access_type ? "RDMA" : "I2C");

	switch (access_type) {
	case MLX_ACCEL_ACCESS_TYPE_RDMA:
		ret = mlx_accel_core_mem_transaction(dev, size, addr, buf,
						     MLX_ACCEL_READ);
		if (ret)
			return ret;
		break;
	case MLX_ACCEL_ACCESS_TYPE_I2C:
		if (!dev->hw_dev)
			return -ENOTCONN;
		ret = mlx_accel_read_i2c(dev->hw_dev, size, addr, buf);
		if (ret)
			return ret;
		break;
	default:
		pr_warn("Unexpected read access_type %u\n", access_type);
		return -EACCES;
	}

	return size;
}
EXPORT_SYMBOL(mlx_accel_core_mem_read);

int mlx_accel_core_mem_write(struct mlx_accel_core_device *dev,
			     size_t size, u64 addr, void *buf,
			     enum mlx_accel_access_type access_type)
{
	int ret;

	if (access_type == MLX_ACCEL_ACCESS_TYPE_DONTCARE)
		access_type = dev->core_conn ? MLX_ACCEL_ACCESS_TYPE_RDMA :
			      MLX_ACCEL_ACCESS_TYPE_I2C;

	pr_debug("**** Writing %lu bytes at 0x%llx using %s\n", size, addr,
		 access_type ? "RDMA" : "I2C");

	switch (access_type) {
	case MLX_ACCEL_ACCESS_TYPE_RDMA:
		ret = mlx_accel_core_mem_transaction(dev, size, addr, buf,
						     MLX_ACCEL_WRITE);
		if (ret)
			return ret;
		break;
	case MLX_ACCEL_ACCESS_TYPE_I2C:
		if (!dev->hw_dev)
			return -ENOTCONN;
		ret = mlx_accel_write_i2c(dev->hw_dev, size, addr, buf);
		if (ret)
			return ret;
		break;
	default:
		pr_warn("Unexpected write access_type %u\n", access_type);
		return -EACCES;
	}

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

int mlx_accel_get_sbu_caps(struct mlx_accel_core_device *dev, int size,
			   void *buf)
{
	u64 addr = MLX5_CAP64_FPGA(dev->hw_dev, sandbox_extended_caps_addr);
	int cap_size = MLX5_CAP_FPGA(dev->hw_dev, sandbox_extended_caps_len);
	int ret;

	pr_debug("Reading %d bytes SBU caps from addr 0x%llx\n", size, addr);

	if (cap_size < size) {
		pr_err("get_sbu_caps: Requested Cap size 0x%8x is bigger than HW size 0x%8x",
		       size, cap_size);
		return -EINVAL;
	}

	ret = mlx_accel_core_mem_read(dev, size, addr, buf,
				      MLX_ACCEL_ACCESS_TYPE_DONTCARE);
	if (ret < 0)
		dev_err(&dev->hw_dev->pdev->dev, "Failed read of SBU caps: %d\n",
			ret);
	else
		ret = 0;
	return ret;
}
EXPORT_SYMBOL(mlx_accel_get_sbu_caps);
