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
#include <linux/mlx5/device.h>

#include "fpga.h"
#include "accel_core.h"
#include "accel_core_xfer.h"

extern struct list_head mlx_accel_core_devices;
extern struct list_head mlx_accel_core_clients;
extern struct mutex mlx_accel_core_mutex;

void mlx_accel_core_client_register(struct mlx_accel_core_client *client)
{
	struct mlx_accel_core_device *accel_device;
	struct mlx_accel_client_data *context;

	pr_debug("mlx_accel_core_client_register %s\n", client->name);

	mutex_lock(&mlx_accel_core_mutex);

	list_add_tail(&client->list, &mlx_accel_core_clients);

	list_for_each_entry(accel_device, &mlx_accel_core_devices, list) {
		context = mlx_accel_client_context_create(accel_device, client);
		if (!context)
			continue;
		mutex_lock(&accel_device->mutex);
		if (accel_device->state == MLX_ACCEL_FPGA_STATUS_SUCCESS)
			if (!client->add(accel_device))
				context->added = true;
		mutex_unlock(&accel_device->mutex);
	}

	mutex_unlock(&mlx_accel_core_mutex);
}
EXPORT_SYMBOL(mlx_accel_core_client_register);

void mlx_accel_core_client_unregister(struct mlx_accel_core_client *client)
{
	struct mlx_accel_core_device *accel_device;
	struct mlx_accel_client_data *context, *tmp_context;

	pr_debug("mlx_accel_core_client_unregister %s\n", client->name);

	mutex_lock(&mlx_accel_core_mutex);

	list_for_each_entry(accel_device, &mlx_accel_core_devices, list) {
		list_for_each_entry_safe(context, tmp_context,
					 &accel_device->client_data_list,
					 list) {
			if (context->client != client)
				continue;
			mutex_lock(&accel_device->mutex);
			if (context->added)
				client->remove(accel_device);
			mutex_unlock(&accel_device->mutex);
			mlx_accel_client_context_destroy(accel_device, context);
			break;
		}
	}

	list_del(&client->list);
	mutex_unlock(&mlx_accel_core_mutex);
}
EXPORT_SYMBOL(mlx_accel_core_client_unregister);

int mlx_accel_core_client_ops_register(struct mlx_accel_core_device *adev,
				       struct mlx5_accel_ops *ops)
{
	int ret = 0;

	ret = mlx5_accel_register(adev->hw_dev, ops);
	if (ret)
		mlx_accel_err(adev, "Failed to register client_ops: %d", ret);
	return ret;
}
EXPORT_SYMBOL(mlx_accel_core_client_ops_register);

void mlx_accel_core_client_ops_unregister(struct mlx_accel_core_device *adev)
{
	mlx5_accel_unregister(adev->hw_dev);
}
EXPORT_SYMBOL(mlx_accel_core_client_ops_unregister);

struct mlx_accel_core_conn *
mlx_accel_core_conn_create(struct mlx_accel_core_device *accel_device,
		struct mlx_accel_core_conn_init_attr *attr)
{
	struct mlx_accel_core_conn *ret;

	mlx_accel_dbg(accel_device, "mlx_accel_core_conn_create\n");

	ret = mlx_accel_core_rdma_conn_create(accel_device, attr, false);
	if (IS_ERR(ret))
		return ret;

	list_add_tail(&ret->list, &accel_device->client_connections);
	return ret;
}
EXPORT_SYMBOL(mlx_accel_core_conn_create);

void mlx_accel_core_conn_destroy(struct mlx_accel_core_conn *conn)
{
	mlx_accel_dbg(conn->accel_device, "mlx_accel_core_conn_destroy\n");

	list_del(&conn->list);
	mlx_accel_core_rdma_conn_destroy(conn);
}
EXPORT_SYMBOL(mlx_accel_core_conn_destroy);

int mlx_accel_core_connect(struct mlx_accel_core_conn *conn)
{
	mlx_accel_dbg(conn->accel_device, "mlx_accel_core_connect\n");

	return mlx_accel_core_rdma_connect(conn);
}
EXPORT_SYMBOL(mlx_accel_core_connect);

int mlx_accel_core_sendmsg(struct mlx_accel_core_conn *conn,
			   struct mlx_accel_core_dma_buf *buf)
{
	return mlx_accel_core_rdma_post_send(conn, buf);
}
EXPORT_SYMBOL(mlx_accel_core_sendmsg);

u64 mlx_accel_core_ddr_size_get(struct mlx_accel_core_device *dev)
{
	return (u64)MLX5_CAP_FPGA(dev->hw_dev, fpga_ddr_size) << 10;
}
EXPORT_SYMBOL(mlx_accel_core_ddr_size_get);

u64 mlx_accel_core_ddr_base_get(struct mlx_accel_core_device *dev)
{
	return MLX5_CAP64_FPGA(dev->hw_dev, fpga_ddr_start_addr);
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

	mlx_accel_dbg(complete->conn->accel_device,
		      "transaction %p complete status %u", complete, status);

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
		mlx_accel_dbg(dev, "Transfer execution failed: %d\n", ret);
		goto out;
	}
	wait_for_completion(&xfer.comp);
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

	mlx_accel_dbg(dev, "Reading %lu bytes at 0x%llx using %s",
		      size, addr, access_type ? "RDMA" : "I2C");

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
		ret = mlx_accel_read_i2c(dev, size, addr, buf);
		if (ret)
			return ret;
		break;
	default:
		mlx_accel_warn(dev, "Unexpected read access_type %u\n",
			       access_type);
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

	mlx_accel_dbg(dev, "Writing %lu bytes at 0x%llx using %s",
		      size, addr, access_type ? "RDMA" : "I2C");

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
		ret = mlx_accel_write_i2c(dev, size, addr, buf);
		if (ret)
			return ret;
		break;
	default:
		mlx_accel_warn(dev, "Unexpected write access_type %u\n",
			       access_type);
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

	list_for_each_entry(context, &accel_device->client_data_list, list) {
		if (context->client != client)
			continue;
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

	list_for_each_entry(context, &accel_device->client_data_list, list) {
		if (context->client != client)
			continue;
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
	return device->class_kobj;
}
EXPORT_SYMBOL(mlx_accel_core_kobj);

int mlx_accel_core_device_reload(struct mlx_accel_core_device *accel_device,
				 enum mlx_accel_fpga_image image)
{
	int err;

	mutex_lock(&accel_device->mutex);
	switch (accel_device->state) {
	case MLX_ACCEL_FPGA_STATUS_NONE:
		err = -ENODEV;
		goto unlock;
	case MLX_ACCEL_FPGA_STATUS_IN_PROGRESS:
		err = -EBUSY;
		goto unlock;
	case MLX_ACCEL_FPGA_STATUS_SUCCESS:
		mlx_accel_device_teardown(accel_device);
		break;
	case MLX_ACCEL_FPGA_STATUS_FAILURE:
		break;
	}
	if (image <= MLX_ACCEL_IMAGE_MAX) {
		err = mlx5_fpga_load(accel_device->hw_dev, image);
		if (err)
			mlx_accel_err(accel_device,
				      "Failed to request FPGA load: %d\n",
				      err);
	} else {
		err = mlx5_fpga_ctrl_op(accel_device->hw_dev,
					MLX5_FPGA_CTRL_OP_RESET);
		if (err)
			mlx_accel_err(accel_device,
				      "Failed to request FPGA reset: %d\n",
				      err);
	}
	accel_device->state = MLX_ACCEL_FPGA_STATUS_IN_PROGRESS;
unlock:
	mutex_unlock(&accel_device->mutex);
	return err;
}
EXPORT_SYMBOL(mlx_accel_core_device_reload);

int mlx_accel_core_flash_select(struct mlx_accel_core_device *accel_device,
				enum mlx_accel_fpga_image image)
{
	int err;

	mutex_lock(&accel_device->mutex);
	switch (accel_device->state) {
	case MLX_ACCEL_FPGA_STATUS_NONE:
		err = -ENODEV;
		goto unlock;
	case MLX_ACCEL_FPGA_STATUS_IN_PROGRESS:
	case MLX_ACCEL_FPGA_STATUS_SUCCESS:
	case MLX_ACCEL_FPGA_STATUS_FAILURE:
		break;
	}

	err = mlx5_fpga_image_select(accel_device->hw_dev, image);
	if (err)
		mlx_accel_err(accel_device,
			      "Failed to select FPGA flash image: %d\n", err);
unlock:
	mutex_unlock(&accel_device->mutex);
	return err;
}
EXPORT_SYMBOL(mlx_accel_core_flash_select);

int mlx_accel_get_sbu_caps(struct mlx_accel_core_device *dev, int size,
			   void *buf)
{
	return mlx5_fpga_sbu_caps(dev->hw_dev, buf, size);
}
EXPORT_SYMBOL(mlx_accel_get_sbu_caps);
