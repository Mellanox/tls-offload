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

#include <rdma/ib_verbs.h>

#include "ipsec_sysfs.h"

struct mlx_ipsec_attribute {
	struct attribute attr;
	ssize_t (*show)(struct mlx_ipsec_dev *dev, char *buf);
	ssize_t (*store)(struct mlx_ipsec_dev *dev, const char *buf,
			size_t count);
};

#define MLX_IPSEC_ATTR(_name, _mode, _show, _store) \
	struct mlx_ipsec_attribute mlx_ipsec_attr_##_name = { \
			.attr = {.name = __stringify(_name), .mode = _mode}, \
			.show = _show, \
			.store = _store, \
	}
#define to_mlx_ipsec_dev(obj)	\
		container_of(kobj, struct mlx_ipsec_dev, kobj)
#define to_mlx_ipsec_attr(_attr)	\
		container_of(attr, struct mlx_ipsec_attribute, attr)

static ssize_t mlx_ipsec_attr_show(struct kobject *kobj, struct attribute *attr,
		char *buf)
{
	struct mlx_ipsec_dev *dev = to_mlx_ipsec_dev(kobj);
	struct mlx_ipsec_attribute *mlx_ipsec_attr = to_mlx_ipsec_attr(attr);
	ssize_t ret = -EIO;

	if (mlx_ipsec_attr->show)
		ret = mlx_ipsec_attr->show(dev, buf);

	return ret;
}

static ssize_t mlx_ipsec_attr_store(struct kobject *kobj,
		struct attribute *attr, const char *buf, size_t count)
{
	struct mlx_ipsec_dev *dev = to_mlx_ipsec_dev(kobj);
	struct mlx_ipsec_attribute *mlx_ipsec_attr = to_mlx_ipsec_attr(attr);
	ssize_t ret = -EIO;

	if (mlx_ipsec_attr->store)
		ret = mlx_ipsec_attr->store(dev, buf, count);

	return ret;
}

static ssize_t mlx_ipsec_sqpn_read(struct mlx_ipsec_dev *dev, char *buf)
{
	return sprintf(buf, "%d\n", dev->conn->qp->qp_num);
}

static ssize_t mlx_ipsec_sgid_read(struct mlx_ipsec_dev *dev, char *buf)
{
	union ib_gid *sgid = &dev->conn->gid;

	return sprintf(buf, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n",
			be16_to_cpu(((__be16 *)sgid->raw)[0]),
			be16_to_cpu(((__be16 *)sgid->raw)[1]),
			be16_to_cpu(((__be16 *)sgid->raw)[2]),
			be16_to_cpu(((__be16 *)sgid->raw)[3]),
			be16_to_cpu(((__be16 *)sgid->raw)[4]),
			be16_to_cpu(((__be16 *)sgid->raw)[5]),
			be16_to_cpu(((__be16 *)sgid->raw)[6]),
			be16_to_cpu(((__be16 *)sgid->raw)[7]));
}

static ssize_t mlx_ipsec_dqpn_read(struct mlx_ipsec_dev *dev, char *buf)
{
	return sprintf(buf, "%d\n", dev->conn->dqpn);
}

static ssize_t mlx_ipsec_dqpn_write(struct mlx_ipsec_dev *dev, const char *buf,
		size_t count)
{
	sscanf(buf, "%u\n", &dev->conn->dqpn);
	/* [SR] TODO: We are planning on keeping this interface in
	 * final version as well? If so, how will we know what DQPN to
	 * use? I guess we should have "allocate-user-QP-slot" API in
	 * the core.
	 */
	mlx_accel_core_connect(dev->conn);
	return count;
}

static ssize_t mlx_ipsec_dgid_read(struct mlx_ipsec_dev *dev, char *buf)
{
	union ib_gid *dgid = &dev->conn->dgid;

	return sprintf(buf, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n",
			be16_to_cpu(((__be16 *)dgid->raw)[0]),
			be16_to_cpu(((__be16 *)dgid->raw)[1]),
			be16_to_cpu(((__be16 *)dgid->raw)[2]),
			be16_to_cpu(((__be16 *)dgid->raw)[3]),
			be16_to_cpu(((__be16 *)dgid->raw)[4]),
			be16_to_cpu(((__be16 *)dgid->raw)[5]),
			be16_to_cpu(((__be16 *)dgid->raw)[6]),
			be16_to_cpu(((__be16 *)dgid->raw)[7]));
}

static ssize_t mlx_ipsec_dgid_write(struct mlx_ipsec_dev *dev, const char *buf,
		size_t count)
{
	union ib_gid *dgid = &dev->conn->dgid;
	int i = 0;
	sscanf(buf, "%04hx:%04hx:%04hx:%04hx:%04hx:%04hx:%04hx:%04hx\n",
			&(((__be16 *) dgid->raw)[0]),
			&(((__be16 *) dgid->raw)[1]),
			&(((__be16 *) dgid->raw)[2]),
			&(((__be16 *) dgid->raw)[3]),
			&(((__be16 *) dgid->raw)[4]),
			&(((__be16 *) dgid->raw)[5]),
			&(((__be16 *) dgid->raw)[6]),
			&(((__be16 *) dgid->raw)[7]));
	for (i = 0; i < 8; i++)
		((__be16 *) dgid->raw)[i] = cpu_to_be16(((u16 *)
			dgid->raw)[i]);
	return count;
}

static MLX_IPSEC_ATTR(sqpn, 0444, mlx_ipsec_sqpn_read, NULL);
static MLX_IPSEC_ATTR(sgid, 0444, mlx_ipsec_sgid_read, NULL);
static MLX_IPSEC_ATTR(dqpn, 0666, mlx_ipsec_dqpn_read, mlx_ipsec_dqpn_write);
static MLX_IPSEC_ATTR(dgid, 0666, mlx_ipsec_dgid_read, mlx_ipsec_dgid_write);

struct attribute *mlx_ipsec_def_attrs[] = {
		&mlx_ipsec_attr_sqpn.attr,
		&mlx_ipsec_attr_sgid.attr,
		&mlx_ipsec_attr_dqpn.attr,
		&mlx_ipsec_attr_dgid.attr,
		NULL,
};

const struct sysfs_ops mlx_ipsec_dev_sysfs_ops = {
	.show  = mlx_ipsec_attr_show,
	.store = mlx_ipsec_attr_store,
};

static struct kobj_type mlx_ipsec_dev_type = {
	.release        = mlx_ipsec_dev_release,
	.sysfs_ops      = &mlx_ipsec_dev_sysfs_ops,
	.default_attrs  = mlx_ipsec_def_attrs,
};

int ipsec_sysfs_init_and_add(struct kobject *kobj,
			 struct kobject *parent, const char *fmt, char *arg)
{
	return kobject_init_and_add(kobj, &mlx_ipsec_dev_type,
			parent,
			fmt, arg);
}

