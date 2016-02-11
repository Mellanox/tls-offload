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

static void mlx_accel_core_add_one(struct ib_device *device)
{
	struct mlx_accel_core_device *accel_device = NULL;
	struct mlx_accel_core_client *client;

	pr_info("mlx_accel_core_add_one called for %s\n", device->name);

	accel_device = kzalloc(sizeof(*accel_device), GFP_KERNEL);
	if (!accel_device)
		return;

	accel_device->device = device;
	accel_device->properties = 0;	/* TODO: get the FPGA properties */

	mutex_lock(&mlx_accel_core_mutex);

	list_for_each_entry(client, &mlx_accel_core_clients, list) {
		/*
		 * TODO: Add a check of client properties against
		 *  the device properties
		 */
		client->add(accel_device);
	}
	list_add_tail(&accel_device->list, &mlx_accel_core_devices);

	mutex_unlock(&mlx_accel_core_mutex);
}

static void mlx_accel_core_remove_one(struct ib_device *device,
				      void *client_data)
{
	struct mlx_accel_core_device *accel_device, *tmp;
	struct mlx_accel_core_client *client;

	pr_info("mlx_accel_core_remove_one called for %s\n", device->name);

	mutex_lock(&mlx_accel_core_mutex);

	list_for_each_entry_safe(accel_device, tmp,
				 &mlx_accel_core_devices, list) {
		if (accel_device->device == device) {
			list_del(&accel_device->list);
			break;
		}
	}
	list_for_each_entry(client, &mlx_accel_core_clients, list) {
		/*
		 * TODO: Add a check of client properties against
		 *  the device properties
		 */
		client->remove(accel_device);
	}

	mutex_unlock(&mlx_accel_core_mutex);

	kfree(accel_device);
}


static struct ib_client mlx_accel_core_ib_client = {
	.name   = "mlx_accel_core",
	.add    = mlx_accel_core_add_one,
	.remove = mlx_accel_core_remove_one
};


static int __init mlx_accel_core_init(void)
{
	ib_register_client(&mlx_accel_core_ib_client);
	return 0;
}

static void __exit mlx_accel_core_exit(void)
{
	ib_unregister_client(&mlx_accel_core_ib_client);
}

module_init(mlx_accel_core_init);
module_exit(mlx_accel_core_exit);
