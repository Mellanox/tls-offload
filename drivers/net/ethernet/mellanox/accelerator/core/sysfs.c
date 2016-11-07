/*
 * Copyright (c) 2004, 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2005 Mellanox Technologies Ltd.  All rights reserved.
 * Copyright (c) 2005 Sun Microsystems, Inc. All rights reserved.
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
 */

#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/netdevice.h>
#include <linux/ethtool.h>
#include "accel_core_sdk.h"

struct accel_attribute {
	struct attribute attr;
	ssize_t (*show)(struct mlx_accel_core_device *, char *);
	ssize_t (*store)(struct mlx_accel_core_device *, const char *, size_t);
};

#define ACCEL_ATTR_RW(_name) \
struct accel_attribute accel_attr_##_name = __ATTR_RW(_name)

#define ACCEL_ATTR_RO(_name) \
struct accel_attribute accel_attr_##_name = __ATTR_RO(_name)

static ssize_t accel_attr_show(struct kobject *kobj, struct attribute *attr,
			       char *buf)
{
	struct accel_attribute *accel_attr =
		container_of(attr, struct accel_attribute, attr);
	struct mlx_accel_core_device *p;

	p = container_of(kobj, struct mlx_accel_core_device, core_kobj);

	if (!accel_attr->show)
		return -EIO;

	return accel_attr->show(p, buf);
}

static const struct sysfs_ops accel_sysfs_ops = {
	.show = accel_attr_show
};

static struct attribute *accel_default_attrs[] = {
	NULL
};

static void accel_release(struct kobject *kobj)
{
}

static struct kobj_type accel_type = {
	.release       = accel_release,
	.sysfs_ops     = &accel_sysfs_ops,
	.default_attrs = accel_default_attrs
};

int mlx_accel_device_register_sysfs(struct mlx_accel_core_device *device)
{
	int ret;
	struct kobject *kobj;

	kobj = kobject_create_and_add("mlx_accel",
				      &device->hw_dev->pdev->dev.kobj);
	if (!kobj) {
		ret = -ENOMEM;
		goto out;
	}

	device->class_kobj = kobj;
	ret = kobject_init_and_add(&device->core_kobj, &accel_type,
				   device->class_kobj, "core");
	if (ret)
		goto err_class_kobj;

	goto out;

err_class_kobj:
	kobject_put(device->class_kobj);
	device->class_kobj = NULL;
out:
	return ret;
}

void mlx_accel_device_unregister_sysfs(struct mlx_accel_core_device *device)
{
	kobject_put(&device->core_kobj);
	kobject_put(device->class_kobj);
}
