/*
 * Copyright (c) 2015 Mellanox Technologies. All rights reserved.
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


/* [BP]: TODO - change these details */
MODULE_AUTHOR("Jhon Snow <Jhon@WinterIsComing.com>");
MODULE_DESCRIPTION("Mellanox FPGA Accelerator Core Driver");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION("0.1");

/* called with mlx_accel_core_mutex locked */
void mlx_accel_core_add_client_to_device(
		struct ib_device *device, u8 port,
		struct mlx_accel_core_client *client)
{
	struct mlx_accel_core_ctx *ctx = NULL;

	pr_info("mlx_accel_core_add_client_to_device called\n");
	if (!client->add) {
		pr_err("Client must have an add function\n");
		return;
	}

	if (!client->remove) {
		pr_err("Client must have an add function\n");
		return;
	}

	ctx             = kzalloc(sizeof(*ctx), GFP_ATOMIC);
	if (!ctx)
		return;

	ctx->ibdev      = device;
	ctx->port_num   = port;
	ctx->client = client;
	list_add_tail(&ctx->list, &mlx_accel_core_ctx_list);
	pr_info("mlx_accel_core_add_client_to_device add called\n");
	client->add(ctx);
}

static void mlx_accel_core_add_one(struct ib_device *device)
{
	u8 port = 0;
	struct mlx_accel_core_client *client = NULL;
	struct mlx_accel_core_accel_device *accel_device =
		kmalloc(sizeof(*accel_device), GFP_ATOMIC);

	pr_info("mlx_accel_core_add_one called\n");

	if (!accel_device)
		return;

	accel_device->device = device;
	/* [BP]: TODO: get the FPGA properties */
	accel_device->properties = 0;

	mutex_lock(&mlx_accel_core_mutex);
	list_add_tail(&accel_device->list, &mlx_accel_core_devices);

	for (port = rdma_start_port(device); port <= rdma_end_port(device);
	     port++) {
		list_for_each_entry(client, &mlx_accel_core_clients, list) {
			/* [BP]: TODO: Add a check of client properties
			 * against the device properties and decide whether to
			 * create a context for this combination of client and
			 * device
			 */
			mlx_accel_core_add_client_to_device(device, port,
					client);
		}
	}
	mutex_unlock(&mlx_accel_core_mutex);
}

static void mlx_accel_core_remove_one(struct ib_device *device,
		void *client_data)
{
	struct mlx_accel_core_ctx *ctx = NULL, *tmp = NULL;
	struct mlx_accel_core_accel_device *accel_device;

	pr_info("mlx_accel_core_remove_one called for %s\n", device->name);

	mutex_lock(&mlx_accel_core_mutex);
	list_for_each_entry(accel_device, &mlx_accel_core_devices, list) {
		if (strncmp(accel_device->device->name, device->name,
					IB_DEVICE_NAME_MAX)) {
			continue;
		}
		list_del(&accel_device->list);
		break;
	}

	list_for_each_entry_safe(ctx, tmp, &mlx_accel_core_ctx_list, list) {
		/* If it's not the device being removed continue */
		if (strncmp(ctx->ibdev->name, device->name,
					IB_DEVICE_NAME_MAX))
			continue;
		/* Remove the device from its clients */
		ctx->client->remove(ctx);
		mlx_accel_core_release(ctx);
	}
	mutex_unlock(&mlx_accel_core_mutex);
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
