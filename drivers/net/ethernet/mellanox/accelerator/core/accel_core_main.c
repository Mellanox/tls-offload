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

#include <linux/module.h>
#include <linux/etherdevice.h>
#include <rdma/ib_mad.h>

#include "accel_core.h"
#include "accel_core_trans.h"

atomic_t mlx_accel_device_id = ATOMIC_INIT(0);
LIST_HEAD(mlx_accel_core_devices);
LIST_HEAD(mlx_accel_core_clients);
/* protects access between client un/registration and device add/remove calls */
DEFINE_MUTEX(mlx_accel_core_mutex);

MODULE_AUTHOR("Ilan Tayari <ilant@mellanox.com>");
MODULE_DESCRIPTION("Mellanox FPGA Accelerator Core Driver");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION("0.1");

void mlx_accel_client_context_del(struct mlx_accel_client_data *context)
{
	pr_debug("Deleting client context %p of client %p\n",
		 context, context->client);
	list_del(&context->list);
	kfree(context);
}

void mlx_accel_client_context_add(struct mlx_accel_core_device *device,
				  struct mlx_accel_core_client *client)
{
	struct mlx_accel_client_data *context;

	/* TODO: If device caps do not match client driver, then
	 * do nothing and return
	 */

	context = kmalloc(sizeof(*context), GFP_KERNEL);
	if (!context) {
		pr_err("Failed to allocate accel device client context\n");
		return;
	}

	context->client = client;
	context->data   = NULL;
	list_add(&context->list, &device->client_data_list);

	pr_debug("Adding client context %p device %p client %p\n",
		 context, device, client);

	if (client->add(device))
		mlx_accel_client_context_del(context);
}

static inline struct mlx_accel_core_device *
	mlx_find_accel_dev_by_hw_dev_unlocked(struct mlx5_core_dev *dev)
{
	struct mlx_accel_core_device *accel_device, *tmp;

	list_for_each_entry_safe(accel_device, tmp, &mlx_accel_core_devices,
			list) {
		if (accel_device->hw_dev == dev)
			goto found;
		if (!accel_device->hw_dev) {
			if (!accel_device->ib_dev) {
				/* [AY]: TODO: do we want to check this case */
				/* [BP]: Yes, WARN_ON could be nice */
				dump_stack();
				pr_err("Found Invalid accel device\n");
				continue;
			}
			if (accel_device->ib_dev->dma_device == &dev->pdev->dev) {
				/* [BP]: Can you move this out of the
				 * function? Currently, this isn't a "find"
				 * function */
				accel_device->hw_dev = dev;
				goto found;
			}
		}
	}

	return NULL;
found:
	return accel_device;
}

static inline struct mlx_accel_core_device *
	mlx_find_accel_dev_by_ib_dev_unlocked(struct ib_device *dev)
{
	struct mlx_accel_core_device *accel_device = NULL, *tmp;

	list_for_each_entry_safe(accel_device, tmp, &mlx_accel_core_devices,
			list) {
		if (accel_device->ib_dev == dev)
			goto found;
		if (!accel_device->ib_dev) {
			if (!accel_device->hw_dev) {
				/* [AY]: TODO: do we want to check this case */
				/* [BP]: Yes, WARN_ON could be nice */
				dump_stack();
				pr_err("Found Invalid accel device\n");
				continue;
			}
			if (&accel_device->hw_dev->pdev->dev == dev->dma_device) {
				/* [BP]: Can you move this out of the
				 * function? Currently, this isn't a "find"
				 * function */
				accel_device->ib_dev = dev;
				goto found;
			}
		}
	}

	return NULL;
found:
	return accel_device;
}

static struct mlx_accel_core_device *mlx_accel_device_alloc(void)
{
	struct mlx_accel_core_device *accel_device = NULL;

	accel_device = kzalloc(sizeof(*accel_device), GFP_KERNEL);
	if (!accel_device)
		return NULL;

	accel_device->properties = 0;	/* TODO: get the FPGA properties */
	accel_device->id = atomic_add_return(1, &mlx_accel_device_id);
	INIT_LIST_HEAD(&accel_device->client_data_list);
	list_add_tail(&accel_device->list, &mlx_accel_core_devices);
	accel_device->port = 1;
	return accel_device;
}

static int mlx_accel_device_init(struct mlx_accel_core_device *accel_device)
{
	struct mlx_accel_core_conn_init_attr core_conn_attr;
	struct mlx_accel_core_client *client;
#ifdef DEBUG
	__be16 *fpga_ip;
#endif
	int err = 0;

	snprintf(accel_device->name, sizeof(accel_device->name), "%s-%s",
		 accel_device->ib_dev->name,
		 accel_device->hw_dev->priv.name);

	err = mlx_accel_fpga_qp_device_init(accel_device);
	if (err) {
		pr_err("Failed to initialize FPGA QP CrSpace: %d\n", err);
		goto out;
	}

	err = ib_find_pkey(accel_device->ib_dev, accel_device->port,
			   IB_DEFAULT_PKEY_FULL, &accel_device->pkey_index);
	if (err) {
		pr_err("Failed to query pkey: %d\n", err);
		goto err_fpga_dev;
	}
	pr_debug("pkey %x index is %u\n", IB_DEFAULT_PKEY_FULL,
		 accel_device->pkey_index);

	err = mlx_accel_trans_device_init(accel_device);
	if (err) {
		pr_err("Failed to initialize transaction machine: %d\n", err);
		goto err_fpga_dev;
	}

	accel_device->pd = ib_alloc_pd(accel_device->ib_dev);
	if (IS_ERR(accel_device->pd)) {
		err = PTR_ERR(accel_device->pd);
		pr_err("Failed to create PD: %d\n", err);
		goto err_trans;
	}

	accel_device->mr = ib_get_dma_mr(accel_device->pd,
					 IB_ACCESS_LOCAL_WRITE |
					 IB_ACCESS_REMOTE_WRITE);
	if (IS_ERR(accel_device->mr)) {
		err = PTR_ERR(accel_device->mr);
		pr_err("Failed to create MR: %d\n", err);
		goto err_pd;
	}

	memset(&core_conn_attr, 0, sizeof(core_conn_attr));
	core_conn_attr.tx_size = MLX_ACCEL_TID_COUNT;
	core_conn_attr.rx_size = MLX_ACCEL_TID_COUNT;
	core_conn_attr.recv_cb = mlx_accel_trans_recv;
	core_conn_attr.cb_arg = accel_device;

	accel_device->core_conn = mlx_accel_core_rdma_conn_create(accel_device,
							&core_conn_attr, true);
	if (IS_ERR(accel_device->core_conn)) {
		err = PTR_ERR(accel_device->core_conn);
		pr_err("Failed to create core RC QP: %d\n", err);
		accel_device->core_conn = NULL;
		goto err_mr;
	}

#ifdef DEBUG
	pr_debug("Local QPN is %u\n", accel_device->core_conn->qp->qp_num);
	fpga_ip = (__be16 *)&accel_device->core_conn->fpga_qpc.fpga_ip;
	pr_debug("FPGA device gid is %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n",
		 ntohs(fpga_ip[0]),
		 ntohs(fpga_ip[1]),
		 ntohs(fpga_ip[2]),
		 ntohs(fpga_ip[3]),
		 ntohs(fpga_ip[4]),
		 ntohs(fpga_ip[5]),
		 ntohs(fpga_ip[6]),
		 ntohs(fpga_ip[7]));
	pr_debug("FPGA QPN is %u\n", accel_device->core_conn->fpga_qpn);
#endif

#ifdef QP_SIMULATOR
	pr_notice("**** QP Simulator mode; Waiting for QP setup ****\n");
#else
	err = mlx_accel_core_rdma_connect(accel_device->core_conn);
	if (err) {
		pr_err("Failed to connect core RC QP to FPGA QP: %d\n", err);
		goto err_core_conn;
	}
#endif

	list_for_each_entry(client, &mlx_accel_core_clients, list)
		mlx_accel_client_context_add(accel_device, client);

	goto out;

err_core_conn:
	mlx_accel_core_rdma_conn_destroy(accel_device->core_conn);
	accel_device->core_conn = NULL;
err_mr:
	ib_dereg_mr(accel_device->mr);
	accel_device->mr = NULL;
err_pd:
	ib_dealloc_pd(accel_device->pd);
	accel_device->pd = NULL;
err_trans:
	mlx_accel_trans_device_deinit(accel_device);
err_fpga_dev:
	mlx_accel_fpga_qp_device_deinit(accel_device);
out:
	return err;
}

static void mlx_accel_device_deinit(struct mlx_accel_core_device *accel_device)
{
	int err = 0;
	struct mlx_accel_client_data *client_context, *tmp;

	if (accel_device->core_conn) {
		list_for_each_entry_safe(client_context, tmp,
					 &accel_device->client_data_list,
					 list) {
			client_context->client->remove(accel_device);
			mlx_accel_client_context_del(client_context);
		}

		mlx_accel_core_rdma_conn_destroy(accel_device->core_conn);
		accel_device->core_conn = NULL;
		err = ib_dereg_mr(accel_device->mr);
		if (err)
			pr_err("Unexpected error deregistering MR: %d\n", err);
		accel_device->mr = NULL;
		ib_dealloc_pd(accel_device->pd);
		accel_device->pd = NULL;
		mlx_accel_trans_device_deinit(accel_device);
		mlx_accel_fpga_qp_device_deinit(accel_device);
	}
}

static void mlx_accel_ib_dev_add_one(struct ib_device *dev)
{
	struct mlx_accel_core_device *accel_device = NULL;

	pr_info("mlx_accel_ib_dev_add_one called for %s\n", dev->name);

	mutex_lock(&mlx_accel_core_mutex);

	accel_device = mlx_find_accel_dev_by_ib_dev_unlocked(dev);
	if (!accel_device) {
		accel_device = mlx_accel_device_alloc();
		if (!accel_device)
			goto out;
		accel_device->ib_dev = dev;
	}

	/* An accel device is ready once it has both IB and HW devices */
	if ((accel_device->ib_dev) && (accel_device->hw_dev))
		mlx_accel_device_init(accel_device);

out:
	mutex_unlock(&mlx_accel_core_mutex);
}

static void mlx_accel_ib_dev_remove_one(struct ib_device *dev,
					void *client_data)
{
	struct mlx_accel_core_device *accel_device;

	pr_info("mlx_accel_ib_dev_remove_one called for %s\n", dev->name);

	mutex_lock(&mlx_accel_core_mutex);

	accel_device = mlx_find_accel_dev_by_ib_dev_unlocked(dev);
	if (!accel_device) {
		pr_err("Not found valid accel device\n");
		goto out;
	}

	if (!accel_device->ib_dev) {
		pr_warn("Removing IB device that was not added\n");
		goto out;
	}

	if (accel_device->hw_dev) {
		mlx_accel_device_deinit(accel_device);
		accel_device->ib_dev = NULL;
	} else {
		list_del(&accel_device->list);
		kfree(accel_device);
	}

out:
	mutex_unlock(&mlx_accel_core_mutex);
}

static void *mlx_accel_hw_dev_add_one(struct mlx5_core_dev *dev)
{
	struct mlx_accel_core_device *accel_device = NULL;

	pr_info("mlx_accel_hw_dev_add_one called for %s\n", dev->priv.name);

	if (!MLX5_CAP_GEN(dev, fpga))
		goto out;

	mutex_lock(&mlx_accel_core_mutex);

	accel_device = mlx_find_accel_dev_by_hw_dev_unlocked(dev);
	if (!accel_device) {
		accel_device = mlx_accel_device_alloc();
		if (!accel_device)
			goto out_unlock;
		accel_device->hw_dev = dev;
	}

	/* An accel device is ready once it has both IB and HW devices */
	if ((accel_device->hw_dev) && (accel_device->ib_dev))
		mlx_accel_device_init(accel_device);

out_unlock:
	mutex_unlock(&mlx_accel_core_mutex);
out:
	return accel_device;
}

static void mlx_accel_hw_dev_remove_one(struct mlx5_core_dev *dev,
		void *context)
{
	struct mlx_accel_core_device *accel_device =
			(struct mlx_accel_core_device *)context;

	pr_info("mlx_accel_hw_dev_remove_one called for %s\n", dev->priv.name);

	mutex_lock(&mlx_accel_core_mutex);

	if (accel_device->ib_dev) {
		mlx_accel_device_deinit(accel_device);
		accel_device->hw_dev = NULL;
	} else {
		list_del(&accel_device->list);
		kfree(accel_device);
	}

	mutex_unlock(&mlx_accel_core_mutex);
}

static void mlx_accel_hw_dev_event_one(struct mlx5_core_dev *mdev,
		void *context, enum mlx5_dev_event event, unsigned long param)
{
	/*
	 * [AY]: TODO: I don't think we need to something with the event,
	 * we will get it throw ibdev or throw netdev
	 */
	pr_debug("mlx_accel_hw_dev_event_one called for %s with %d\n",
			mdev->priv.name, event);
}


static struct ib_client mlx_accel_ib_client = {
		.name   = "mlx_accel_core",
		.add    = mlx_accel_ib_dev_add_one,
		.remove = mlx_accel_ib_dev_remove_one
};

static struct mlx5_interface mlx_accel_hw_intf  = {
		.add = mlx_accel_hw_dev_add_one,
		.remove = mlx_accel_hw_dev_remove_one,
		.event = mlx_accel_hw_dev_event_one
};

static int __init mlx_accel_core_init(void)
{
	int rc;
	rc = mlx5_register_interface(&mlx_accel_hw_intf);
	if (rc) {
		pr_err("mlx5_register_interface failed\n");
		goto err;
	}

	rc = ib_register_client(&mlx_accel_ib_client);
	if (rc) {
		pr_err("ib_register_client failed\n");
		goto err_register_intf;
	}

	return 0;
err_register_intf:
	mlx5_unregister_interface(&mlx_accel_hw_intf);
err:
	return rc;
}

static void __exit mlx_accel_core_exit(void)
{
	ib_unregister_client(&mlx_accel_ib_client);
	mlx5_unregister_interface(&mlx_accel_hw_intf);
}

module_init(mlx_accel_core_init);
module_exit(mlx_accel_core_exit);
