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

#include "accel_core.h"


LIST_HEAD(mlx_accel_core_devices);
LIST_HEAD(mlx_accel_core_clients);
/* protects access between client un/registeration and device add/remove calls
 */
DEFINE_MUTEX(mlx_accel_core_mutex);

/* [BP]: TODO - change these details */
MODULE_AUTHOR("Jhon Snow <Jhon@WinterIsComing.com>");
MODULE_DESCRIPTION("Mellanox FPGA Accelerator Core Driver");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION("0.1");

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
				dump_stack();
				pr_err("Found Invalid accel device\n");
				continue;
			}
			if (accel_device->ib_dev->dma_device == &dev->pdev->dev) {
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
				dump_stack();
				pr_err("Found Invalid accel device\n");
				continue;
			}
			if (&accel_device->hw_dev->pdev->dev == dev->dma_device) {
				accel_device->ib_dev = dev;
				goto found;
			}
		}
	}

	return NULL;
found:
	return accel_device;
}

static void mlx_accel_ib_dev_add_one(struct ib_device *dev)
{
	struct mlx_accel_core_device *accel_device = NULL;
	struct mlx_accel_core_client *client;

	pr_info("mlx_accel_ib_dev_add_one called for %s\n", dev->name);

	mutex_lock(&mlx_accel_core_mutex);

	accel_device = mlx_find_accel_dev_by_ib_dev_unlocked(dev);
	if (!accel_device) {
		accel_device = kzalloc(sizeof(*accel_device), GFP_KERNEL);
		if (!accel_device)
			return;

		accel_device->ib_dev = dev;
		accel_device->properties = 0;	/* TODO: get the FPGA properties */
		list_add_tail(&accel_device->list, &mlx_accel_core_devices);
	}

	if ((accel_device->ib_dev) && (accel_device->hw_dev)) {
		list_for_each_entry(client, &mlx_accel_core_clients, list) {
			/*
			 * TODO: Add a check of client properties against
			 *  the device properties
			 */
			client->add(accel_device);
		}
		sprintf(accel_device->name, "%s-%s", accel_device->ib_dev->name,
				accel_device->hw_dev->priv.name);
	}

	mutex_unlock(&mlx_accel_core_mutex);
}

static void mlx_accel_core_remove_one(struct ib_device *device,
					void *client_data)
{
	struct mlx_accel_core_device *accel_device;
	struct mlx_accel_core_client *client;

	pr_info("mlx_accel_core_remove_one called for %s\n", dev->name);

	mutex_lock(&mlx_accel_core_mutex);

	accel_device = mlx_find_accel_dev_by_ib_dev_unlocked(dev);
	if (!accel_device) {
		/* [AY]: TODO: do we want to check this case */
		dump_stack();
		pr_err("Not found valid accel device\n");
		return;
	}

	accel_device->ib_dev = NULL;
	if (accel_device->hw_dev) {
		list_for_each_entry(client, &mlx_accel_core_clients, list) {
			/*
			 * TODO: Add a check of client properties against
			 *  the device properties
			 */
			client->remove(accel_device);
		}
	} else {
		list_del(&accel_device->list);
		kfree(accel_device);
	}

	mutex_unlock(&mlx_accel_core_mutex);
}

static void *mlx_accel_hw_dev_add_one(struct mlx5_core_dev *dev)
{
	struct mlx_accel_core_device *accel_device = NULL;
	struct mlx_accel_core_client *client;

	pr_info("mlx_accel_hw_dev_add_one called for %s\n", dev->priv.name);

	mutex_lock(&mlx_accel_core_mutex);

	accel_device = mlx_find_accel_dev_by_hw_dev_unlocked(dev);
	if (!accel_device) {
		accel_device = kzalloc(sizeof(*accel_device), GFP_KERNEL);
		if (!accel_device)
			return NULL;

		accel_device->hw_dev = dev;
		accel_device->properties = 0;	/* TODO: get the FPGA properties */
		list_add_tail(&accel_device->list, &mlx_accel_core_devices);
	}

	if ((accel_device->hw_dev) && (accel_device->ib_dev)) {
		list_for_each_entry(client, &mlx_accel_core_clients, list) {
			/*
			 * TODO: Add a check of client properties against
			 *  the device properties
			 */
			client->add(accel_device);
		}
		sprintf(accel_device->name, "%s-%s", accel_device->ib_dev->name,
				accel_device->hw_dev->priv.name);
	}

	mutex_unlock(&mlx_accel_core_mutex);
	return accel_device;
}

static void mlx_accel_hw_dev_remove_one(struct mlx5_core_dev *dev,
		void *context)
{
	struct mlx_accel_core_device *accel_device =
			(struct mlx_accel_core_device *)context;
	struct mlx_accel_core_client *client;

	pr_info("mlx_accel_hw_dev_remove_one called for %s\n", dev->priv.name);

	mutex_lock(&mlx_accel_core_mutex);

	accel_device->hw_dev = NULL;
	if (accel_device->ib_dev) {
		list_for_each_entry(client, &mlx_accel_core_clients, list) {
			/*
			 * TODO: Add a check of client properties against
			 *  the device properties
			 */
			client->remove(accel_device);
		}
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
