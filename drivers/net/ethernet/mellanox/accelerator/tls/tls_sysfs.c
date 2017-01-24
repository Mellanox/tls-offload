/*
 * Copyright (c) 2015-2017 Mellanox Technologies. All rights reserved.
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

#include "tls_sysfs.h"
#include "tls_cmds.h"

#if IS_ENABLED(CONFIG_MLX5_CORE_FPGA_QP_SIM)
#ifdef MLX_TLS_SADB_RDMA
struct mlx_tls_attribute {
	struct attribute attr;
	ssize_t (*show)(struct mlx_tls_dev *dev, char *buf);
	ssize_t (*store)(struct mlx_tls_dev *dev, const char *buf,
			 size_t count);
};

#define MLX_IPSEC_ATTR(_name, _mode, _show, _store) \
	struct mlx_tls_attribute mlx_tls_attr_##_name = { \
			.attr = {.name = __stringify(_name), .mode = _mode}, \
			.show = _show, \
			.store = _store, \
	}
#define to_mlx_tls_dev(obj)	\
		container_of(kobj, struct mlx_tls_dev, kobj)
#define to_mlx_tls_attr(_attr)	\
		container_of(attr, struct mlx_tls_attribute, attr)

static ssize_t mlx_tls_attr_show(struct kobject *kobj, struct attribute *attr,
				 char *buf)
{
	struct mlx_tls_dev *dev = to_mlx_tls_dev(kobj);
	struct mlx_tls_attribute *mlx_tls_attr = to_mlx_tls_attr(attr);
	ssize_t ret = -EIO;

	if (mlx_tls_attr->show)
		ret = mlx_tls_attr->show(dev, buf);

	return ret;
}

static ssize_t mlx_tls_attr_store(struct kobject *kobj, struct attribute *attr,
				  const char *buf, size_t count)
{
	struct mlx_tls_dev *dev = to_mlx_tls_dev(kobj);
	struct mlx_tls_attribute *mlx_tls_attr = to_mlx_tls_attr(attr);
	ssize_t ret = -EIO;

	if (mlx_tls_attr->store)
		ret = mlx_tls_attr->store(dev, buf, count);

	return ret;
}

static ssize_t mlx_tls_sqpn_read(struct mlx_tls_dev *dev, char *buf)
{
	return sprintf(buf, "%u\n", dev->conn->qp->qp_num);
}

static ssize_t mlx_tls_sgid_read(struct mlx_tls_dev *dev, char *buf)
{
	union ib_gid *sgid = (union ib_gid *)&dev->conn->fpga_qpc.remote_ip;

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

static ssize_t mlx_tls_dqpn_read(struct mlx_tls_dev *dev, char *buf)
{
	return sprintf(buf, "%u\n", dev->conn->fpga_qpn);
}

static ssize_t mlx_tls_dqpn_write(struct mlx_tls_dev *dev, const char *buf,
				  size_t count)
{
	int tmp;

	tmp = sscanf(buf, "%u\n", &dev->conn->fpga_qpn);
	mlx_accel_core_connect(dev->conn);

	return count;
}

static ssize_t mlx_tls_dgid_read(struct mlx_tls_dev *dev, char *buf)
{
	union ib_gid *dgid = (union ib_gid *)&dev->conn->fpga_qpc.fpga_ip;

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

static ssize_t mlx_tls_dgid_write(struct mlx_tls_dev *dev, const char *buf,
				  size_t count)
{
	union ib_gid *dgid = (union ib_gid *)&dev->conn->fpga_qpc.fpga_ip;
	int i = 0;
	int tmp;

	tmp = sscanf(buf,
		     "%04hx:%04hx:%04hx:%04hx:%04hx:%04hx:%04hx:%04hx\n",
		     &(((__be16 *)dgid->raw)[0]),
		     &(((__be16 *)dgid->raw)[1]),
		     &(((__be16 *)dgid->raw)[2]),
		     &(((__be16 *)dgid->raw)[3]),
		     &(((__be16 *)dgid->raw)[4]),
		     &(((__be16 *)dgid->raw)[5]),
		     &(((__be16 *)dgid->raw)[6]),
		     &(((__be16 *)dgid->raw)[7]));

	for (i = 0; i < 8; i++)
		((__be16 *)dgid->raw)[i] = cpu_to_be16(((u16 *)dgid->raw)[i]);

	return count;
}

static void mlx_tls_dev_release(struct kobject *kobj)
{
}

static MLX_IPSEC_ATTR(sqpn, 0444, mlx_tls_sqpn_read, NULL);
static MLX_IPSEC_ATTR(sgid, 0444, mlx_tls_sgid_read, NULL);
static MLX_IPSEC_ATTR(dqpn, 0666, mlx_tls_dqpn_read, mlx_tls_dqpn_write);
static MLX_IPSEC_ATTR(dgid, 0666, mlx_tls_dgid_read, mlx_tls_dgid_write);

struct attribute *mlx_tls_def_attrs[] = {
		&mlx_tls_attr_sqpn.attr,
		&mlx_tls_attr_sgid.attr,
		&mlx_tls_attr_dqpn.attr,
		&mlx_tls_attr_dgid.attr,
		NULL,
};

const struct sysfs_ops mlx_tls_dev_sysfs_ops = {
	.show  = mlx_tls_attr_show,
	.store = mlx_tls_attr_store,
};

static struct kobj_type mlx_tls_dev_type = {
	.release        = mlx_tls_dev_release,
	.sysfs_ops      = &mlx_tls_dev_sysfs_ops,
	.default_attrs  = mlx_tls_def_attrs,
};

int tls_sysfs_init_and_add(struct kobject *kobj, struct kobject *parent,
			   const char *fmt, char *arg)
{
	return kobject_init_and_add(kobj, &mlx_tls_dev_type,
			parent,
			fmt, arg);
}
#endif
#endif
