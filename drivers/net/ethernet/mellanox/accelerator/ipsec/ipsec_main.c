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

#include "ipsec.h"
#include "ipsec_hw.h"

MODULE_AUTHOR("Boris Pismenny <borisp@mellanox.com>");
MODULE_AUTHOR("Ilan Tayari <ilant@mellanox.com>");
MODULE_DESCRIPTION("Mellanox Innova IPsec Driver");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION(DRIVER_VERSION);

/* [BP] TODO: add capabilities */
static struct mlx_accel_core_client mlx_ipsec_client = {
	.name   = "mlx_ipsec",
	.add    = mlx_ipsec_add_one,
	.remove = mlx_ipsec_remove_one,
};

static struct notifier_block mlx_ipsec_netdev_notifier = {
	.notifier_call = mlx_ipsec_netdev_event,
};

static int __init mlx_ipsec_init(void)
{
	int err = 0;

	mlx_ipsec_init_inverse_table();

	err = register_netdevice_notifier(&mlx_ipsec_netdev_notifier);
	if (err) {
		pr_warn("mlx_ipsec_init error in register_netdevice_notifier %d\n",
				err);
		goto out;
	}

	mlx_accel_core_client_register(&mlx_ipsec_client);

out:
	return err;
}

static void __exit mlx_ipsec_exit(void)
{
	/* [BP]: TODO - delete all SA entries. Verify that no inflight packets
	 * are going to be offloaded while we are unloading
	 */
	mlx_accel_core_client_unregister(&mlx_ipsec_client);
	unregister_netdevice_notifier(&mlx_ipsec_netdev_notifier);
}

module_init(mlx_ipsec_init);
module_exit(mlx_ipsec_exit);


