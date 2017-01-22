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
#include <linux/mlx5_ib/driver.h>

#include "fpga.h"
#include "accel_core.h"
#include "accel_core_trans.h"

static struct workqueue_struct *mlx_accel_core_workq;
LIST_HEAD(mlx_accel_core_devices);
LIST_HEAD(mlx_accel_core_clients);
/* protects access between client un/registration and device add/remove calls */
DEFINE_MUTEX(mlx_accel_core_mutex);

MODULE_AUTHOR("Ilan Tayari <ilant@mellanox.com>");
MODULE_DESCRIPTION("Mellanox Innova Core Driver");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION("0.1");

static const char * const mlx_accel_fpga_error_string[] = {
	"Null Syndrome",
	"Corrupted DDR",
	"Flash Timeout",
	"Internal Link Error",
	"Watchdog HW Failure",
	"I2C Failure",
	"Image Changed",
};

static const char * const mlx_accel_fpga_qp_error_string[] = {
	"Null Syndrome",
	"Retry Counter Expired",
	"RNR Expired",
};

static int mlx_accel_core_workq_init(void)
{
	mlx_accel_core_workq = create_workqueue("mlx_accel_core");
	if (!mlx_accel_core_workq)
		return -ENOMEM;
	return 0;
}

static void mlx_accel_core_workq_deinit(void)
{
	flush_workqueue(mlx_accel_core_workq);
	destroy_workqueue(mlx_accel_core_workq);
	mlx_accel_core_workq = NULL;
}

void mlx_accel_client_context_destroy(struct mlx_accel_core_device *device,
				      struct mlx_accel_client_data *context)
{
	pr_debug("Deleting client context %p of client %p\n",
		 context, context->client);
	if (context->client->destroy)
		context->client->destroy(device);
	list_del(&context->list);
	kfree(context);
}

struct mlx_accel_client_data *
mlx_accel_client_context_create(struct mlx_accel_core_device *device,
				struct mlx_accel_core_client *client)
{
	struct mlx_accel_client_data *context;

	/* TODO: If device caps do not match client driver, then
	 * do nothing and return
	 */

	context = kmalloc(sizeof(*context), GFP_KERNEL);
	if (!context) {
		pr_err("Failed to allocate accel device client context\n");
		return NULL;
	}

	context->client = client;
	context->data   = NULL;
	context->added  = false;
	list_add(&context->list, &device->client_data_list);

	pr_debug("Adding client context %p device %p client %p\n",
		 context, device, client);

	if (client->create)
		client->create(device);
	return context;
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

	mutex_init(&accel_device->mutex);
	accel_device->state = MLX_ACCEL_FPGA_STATUS_NONE;
	INIT_LIST_HEAD(&accel_device->client_data_list);
	INIT_LIST_HEAD(&accel_device->client_connections);
	list_add_tail(&accel_device->list, &mlx_accel_core_devices);
	accel_device->port = 1;
	return accel_device;
}

static void mlx_accel_device_init(struct mlx_accel_core_device *accel_device)
{
	struct mlx_accel_core_conn_init_attr core_conn_attr;
	struct mlx_accel_client_data *client_context;
#ifdef DEBUG
	__be16 *fpga_ip;
#endif
	int err = 0;

	err = ib_find_pkey(accel_device->ib_dev, accel_device->port,
			   IB_DEFAULT_PKEY_FULL, &accel_device->pkey_index);
	if (err) {
		dev_err(&accel_device->hw_dev->pdev->dev,
			"Failed to query pkey: %d\n", err);
		goto out;
	}
	pr_debug("pkey %x index is %u\n", IB_DEFAULT_PKEY_FULL,
		 accel_device->pkey_index);

	err = mlx_accel_trans_device_init(accel_device);
	if (err) {
		dev_err(&accel_device->hw_dev->pdev->dev,
			"Failed to initialize transaction machine: %d\n", err);
		goto out;
	}

	accel_device->pd = ib_alloc_pd(accel_device->ib_dev, 0);
	if (IS_ERR(accel_device->pd)) {
		err = PTR_ERR(accel_device->pd);
		dev_err(&accel_device->hw_dev->pdev->dev,
			"Failed to create PD: %d\n", err);
		goto err_trans;
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
		dev_err(&accel_device->hw_dev->pdev->dev,
			"Failed to create core RC QP: %d\n", err);
		accel_device->core_conn = NULL;
		goto err_pd;
	}

#ifdef DEBUG
	dev_dbg(&accel_device->hw_dev->pdev->dev,
		"Local QPN is %u\n", accel_device->core_conn->qp->qp_num);
	fpga_ip = (__be16 *)&accel_device->core_conn->fpga_qpc.fpga_ip;
	dev_dbg(&accel_device->hw_dev->pdev->dev,
		"FPGA device gid is %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n",
		ntohs(fpga_ip[0]), ntohs(fpga_ip[1]),
		ntohs(fpga_ip[2]), ntohs(fpga_ip[3]),
		ntohs(fpga_ip[4]), ntohs(fpga_ip[5]),
		ntohs(fpga_ip[6]), ntohs(fpga_ip[7]));
	dev_dbg(&accel_device->hw_dev->pdev->dev,
		"FPGA QPN is %u\n", accel_device->core_conn->fpga_qpn);
#endif

	err = mlx_accel_core_rdma_connect(accel_device->core_conn);
	if (err) {
		dev_err(&accel_device->hw_dev->pdev->dev,
			"Failed to connect core RC QP to FPGA QP: %d\n", err);
		goto err_core_conn;
	}

	if (accel_device->last_oper_image == MLX_ACCEL_IMAGE_USER) {
		err = mlx5_fpga_ctrl_op(accel_device->hw_dev,
					MLX5_FPGA_CTRL_OP_SB_BYPASS_ON);
		if (err) {
			dev_err(&accel_device->hw_dev->pdev->dev,
				"Failed to set SBU bypass on: %d\n", err);
			goto err_core_conn;
		}
		err = mlx5_fpga_ctrl_op(accel_device->hw_dev,
					MLX5_FPGA_CTRL_OP_RESET_SB);
		if (err) {
			dev_err(&accel_device->hw_dev->pdev->dev,
				"Failed to reset SBU: %d\n", err);
			/* TODO: Workaround for bug #891929
			 * goto err_core_conn;
			 */
		}
		err = mlx5_fpga_ctrl_op(accel_device->hw_dev,
					MLX5_FPGA_CTRL_OP_SB_BYPASS_OFF);
		if (err) {
			dev_err(&accel_device->hw_dev->pdev->dev,
				"Failed to set SBU bypass off: %d\n", err);
			goto err_core_conn;
		}

		list_for_each_entry(client_context,
				    &accel_device->client_data_list, list) {
			if (client_context->client->add(accel_device))
				continue;
			client_context->added = true;
		}
	}

	goto out;

err_core_conn:
	mlx_accel_core_rdma_conn_destroy(accel_device->core_conn);
	accel_device->core_conn = NULL;
err_pd:
	ib_dealloc_pd(accel_device->pd);
	accel_device->pd = NULL;
err_trans:
	mlx_accel_trans_device_deinit(accel_device);
out:
	accel_device->state = err ? MLX_ACCEL_FPGA_STATUS_FAILURE :
				    MLX_ACCEL_FPGA_STATUS_SUCCESS;
}

void mlx_accel_device_teardown(struct mlx_accel_core_device *accel_device)
{
	int err = 0;
	struct mlx_accel_client_data *client_context;

	if ((accel_device->state == MLX_ACCEL_FPGA_STATUS_SUCCESS) &&
	    (accel_device->last_oper_image == MLX_ACCEL_IMAGE_USER)) {
		err = mlx5_fpga_ctrl_op(accel_device->hw_dev,
					MLX5_FPGA_CTRL_OP_SB_BYPASS_ON);
		if (err) {
			dev_err(&accel_device->hw_dev->pdev->dev,
				"Failed to re-set SBU bypass on: %d\n", err);
		}
	}

	list_for_each_entry(client_context,
			    &accel_device->client_data_list, list) {
		if (!client_context->added)
			continue;
		client_context->client->remove(accel_device);
		client_context->added = false;
	}
	WARN_ON(!list_empty(&accel_device->client_connections));

	if (accel_device->core_conn) {
		mlx_accel_core_rdma_conn_destroy(accel_device->core_conn);
		accel_device->core_conn = NULL;
		ib_dealloc_pd(accel_device->pd);
		accel_device->pd = NULL;
		mlx_accel_trans_device_deinit(accel_device);
	}
}

static void mlx_accel_device_check(struct mlx_accel_core_device *accel_device)
{
	enum mlx_accel_fpga_status status = 0;
	int err;

	err = mlx5_fpga_query(accel_device->hw_dev,
			      &status, &accel_device->last_admin_image,
			      &accel_device->last_oper_image);
	if (err) {
		dev_err(&accel_device->hw_dev->pdev->dev,
			"Failed to query FPGA status: %d\n", err);
		return;
	}

	switch (status) {
	case MLX_ACCEL_FPGA_STATUS_SUCCESS:
		dev_info(&accel_device->hw_dev->pdev->dev,
			 "FPGA image is ready\n");
		mlx_accel_device_init(accel_device);
		break;
	case MLX_ACCEL_FPGA_STATUS_FAILURE:
		accel_device->state = MLX_ACCEL_FPGA_STATUS_FAILURE;
		dev_info(&accel_device->hw_dev->pdev->dev,
			 "FPGA device has failed\n");
		break;
	case MLX_ACCEL_FPGA_STATUS_IN_PROGRESS:
		accel_device->state = MLX_ACCEL_FPGA_STATUS_IN_PROGRESS;
		dev_info(&accel_device->hw_dev->pdev->dev,
			 "FPGA device is not ready yet\n");
		break;
	default:
		dev_err(&accel_device->hw_dev->pdev->dev,
			"FPGA status unknown: %u\n", status);
		break;
	}
}

static void mlx_accel_device_start(struct mlx_accel_core_device *accel_device)
{
	struct mlx_accel_core_client *client;

	snprintf(accel_device->name, sizeof(accel_device->name), "%s-%s",
		 accel_device->ib_dev->name,
		 accel_device->hw_dev->priv.name);

	mlx_accel_device_register_sysfs(accel_device);

	list_for_each_entry(client, &mlx_accel_core_clients, list)
		mlx_accel_client_context_create(accel_device, client);

	mutex_lock(&accel_device->mutex);
	mlx_accel_device_check(accel_device);
	mutex_unlock(&accel_device->mutex);
}

static void mlx_accel_device_stop(struct mlx_accel_core_device *accel_device)
{
	struct mlx_accel_client_data *context, *tmp;

	mutex_lock(&accel_device->mutex);
	mlx_accel_device_teardown(accel_device);
	accel_device->state = MLX_ACCEL_FPGA_STATUS_NONE;
	mutex_unlock(&accel_device->mutex);

	list_for_each_entry_safe(context, tmp, &accel_device->client_data_list,
				 list)
		mlx_accel_client_context_destroy(accel_device, context);

	mlx_accel_device_unregister_sysfs(accel_device);
}

static void mlx_accel_ib_dev_add_one(struct ib_device *ibdev)
{
	struct mlx_accel_core_device *accel_device = NULL;
	struct mlx5_core_dev *mdev =  mlx5_get_mdev_from_ibdev(ibdev);

	if (!MLX5_CAP_GEN(mdev, fpga)) {
		dev_dbg(&ibdev->dev, "FPGA device not present\n");
		return;
	}

	dev_info(&ibdev->dev, "mlx_accel_ib_dev_add_one called\n");

	mutex_lock(&mlx_accel_core_mutex);

	accel_device = mlx_find_accel_dev_by_ib_dev_unlocked(ibdev);
	if (!accel_device) {
		accel_device = mlx_accel_device_alloc();
		if (!accel_device)
			goto out;
		accel_device->ib_dev = ibdev;
	}

	/* An accel device is ready once it has both IB and HW devices */
	if ((accel_device->ib_dev) && (accel_device->hw_dev))
		mlx_accel_device_start(accel_device);

out:
	mutex_unlock(&mlx_accel_core_mutex);
}

static void mlx_accel_ib_dev_remove_one(struct ib_device *ibdev,
					void *client_data)
{
	struct mlx_accel_core_device *accel_device;

	mutex_lock(&mlx_accel_core_mutex);

	accel_device = mlx_find_accel_dev_by_ib_dev_unlocked(ibdev);
	if (!accel_device) {
		dev_dbg(&ibdev->dev, "Not found valid accel device\n");
		goto out;
	}

	if (!accel_device->ib_dev) {
		pr_warn("Removing IB device that was not added\n");
		goto out;
	}

	if (accel_device->hw_dev) {
		mlx_accel_device_stop(accel_device);
		accel_device->ib_dev = NULL;
	} else {
		list_del(&accel_device->list);
		kfree(accel_device);
	}

	dev_info(&ibdev->dev, "mlx_accel_ib_dev_remove_one called\n");

out:
	mutex_unlock(&mlx_accel_core_mutex);
}

static void *mlx_accel_hw_dev_add_one(struct mlx5_core_dev *dev)
{
	struct mlx_accel_core_device *accel_device = NULL;

	if (!MLX5_CAP_GEN(dev, fpga)) {
		pr_debug("FPGA device not present for %s\n", dev->priv.name);
		goto out;
	}

	pr_info("mlx_accel_hw_dev_add_one called for %s\n", dev->priv.name);

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
		mlx_accel_device_start(accel_device);

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

	mutex_lock(&mlx_accel_core_mutex);

	if (accel_device->ib_dev) {
		mlx_accel_device_stop(accel_device);
		accel_device->hw_dev = NULL;
	} else {
		list_del(&accel_device->list);
		kfree(accel_device);
	}

	pr_info("mlx_accel_hw_dev_remove_one called for %s\n", dev->priv.name);

	mutex_unlock(&mlx_accel_core_mutex);
}

static const char *mlx_accel_error_string(u8 syndrome)
{
	if (syndrome < ARRAY_SIZE(mlx_accel_fpga_error_string))
		return mlx_accel_fpga_error_string[syndrome];
	return "Unknown";
}

static const char *mlx_accel_qp_error_string(u8 syndrome)
{
	if (syndrome < ARRAY_SIZE(mlx_accel_fpga_qp_error_string))
		return mlx_accel_fpga_qp_error_string[syndrome];
	return "Unknown";
}

struct my_work {
	struct work_struct work;
	struct mlx_accel_core_device *accel_device;
	u8 syndrome;
	u32 fpga_qpn;
};

static void mlx_accel_fpga_error(struct work_struct *work)
{
	struct my_work *mywork = container_of(work, struct my_work, work);
	struct mlx_accel_core_device *accel_device = mywork->accel_device;
	u8 syndrome = mywork->syndrome;

	mutex_lock(&accel_device->mutex);
	switch (accel_device->state) {
	case MLX_ACCEL_FPGA_STATUS_NONE:
	case MLX_ACCEL_FPGA_STATUS_FAILURE:
		dev_warn(&accel_device->hw_dev->pdev->dev,
			 "Unexpected FPGA event %u: %s\n",
			 syndrome, mlx_accel_error_string(syndrome));
		break;
	case MLX_ACCEL_FPGA_STATUS_IN_PROGRESS:
		if (syndrome != MLX5_FPGA_ERROR_EVENT_SYNDROME_IMAGE_CHANGED)
			dev_warn(&accel_device->hw_dev->pdev->dev,
				 "FPGA Error while loading %u: %s\n",
				 syndrome, mlx_accel_error_string(syndrome));
		else
			mlx_accel_device_check(accel_device);
		break;
	case MLX_ACCEL_FPGA_STATUS_SUCCESS:
		mlx_accel_device_teardown(accel_device);
		dev_err(&accel_device->hw_dev->pdev->dev,
			"FPGA Error %u: %s\n",
			syndrome, mlx_accel_error_string(syndrome));
		accel_device->state = MLX_ACCEL_FPGA_STATUS_FAILURE;
		break;
	}
	mutex_unlock(&accel_device->mutex);
	kfree(mywork);
}

static void mlx_accel_fpga_qp_error(struct work_struct *work)
{
	struct my_work *mywork = container_of(work, struct my_work, work);
	struct mlx_accel_core_device *accel_device = mywork->accel_device;
	u8 syndrome = mywork->syndrome;
	u32 fpga_qpn = mywork->fpga_qpn;

	dev_warn(&accel_device->ib_dev->dev,
		 "FPGA Error %u on QP %u: %s\n",
		 syndrome, fpga_qpn, mlx_accel_qp_error_string(syndrome));
	kfree(mywork);
}

static void mlx_accel_hw_dev_event_one(struct mlx5_core_dev *mdev,
				       void *context, enum mlx5_dev_event event,
				       unsigned long param)
{
	struct my_work *work;
	struct mlx_accel_core_device *accel_device = context;

	if ((event != MLX5_DEV_EVENT_FPGA_ERROR) &&
	    (event != MLX5_DEV_EVENT_FPGA_QP_ERROR))
		return;

	work = kzalloc(sizeof(*work), GFP_ATOMIC);
	if (!work)
		return;

	work->accel_device = accel_device;

	switch (event) {
	case MLX5_DEV_EVENT_FPGA_ERROR:
		INIT_WORK(&work->work, mlx_accel_fpga_error);
		work->syndrome = MLX5_GET(fpga_error_event,
					  (void *)param, syndrome);
		break;
	case MLX5_DEV_EVENT_FPGA_QP_ERROR:
		INIT_WORK(&work->work, mlx_accel_fpga_qp_error);
		work->syndrome = MLX5_GET(fpga_qp_error_event,
					  (void *)param, syndrome);
		work->fpga_qpn = MLX5_GET(fpga_qp_error_event,
					  (void *)param, fpga_qpn);
		break;
	default:
		break;
	}
	queue_work(mlx_accel_core_workq, &work->work);
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

	rc = mlx_accel_core_workq_init();
	if (rc) {
		pr_err("mlx_accel_core failed to create event workq\n");
		goto err;
	}

	rc = mlx5_register_interface(&mlx_accel_hw_intf);
	if (rc) {
		pr_err("mlx5_register_interface failed\n");
		goto err_workq;
	}

	rc = ib_register_client(&mlx_accel_ib_client);
	if (rc) {
		pr_err("ib_register_client failed\n");
		goto err_register_intf;
	}

	return 0;

err_register_intf:
	mlx5_unregister_interface(&mlx_accel_hw_intf);
err_workq:
	mlx_accel_core_workq_deinit();
err:
	return rc;
}

static void __exit mlx_accel_core_exit(void)
{
	ib_unregister_client(&mlx_accel_ib_client);
	mlx5_unregister_interface(&mlx_accel_hw_intf);
	mlx_accel_core_workq_deinit();
}

module_init(mlx_accel_core_init);
module_exit(mlx_accel_core_exit);
