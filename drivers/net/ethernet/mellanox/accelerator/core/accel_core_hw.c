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

#include "accel_core.h"
#include <linux/etherdevice.h>
#include <linux/mlx5/device.h>
#include <linux/mlx5/driver.h>
#include <rdma/ib_mad.h>

int mlx_accel_read_i2c(struct mlx5_core_dev *dev,
		       size_t size, u64 addr, u8 *buf)
{
	u8 actual_size;
	size_t bytes_done = 0;
	size_t max_size = MLX5_FPGA_ACCESS_REG_SIZE_MAX;
	int rc;

	while (bytes_done < size) {
		actual_size = min(max_size, (size - bytes_done));

		rc = mlx5_fpga_access_reg(dev, actual_size,
					  addr + bytes_done,
					  buf + bytes_done, false);
		if (rc) {
			pr_err("Failed to read FPGA crspace data for %s\n",
			       dev_name(&dev->pdev->dev));
			return rc;
		}

		bytes_done += actual_size;
	}

	return 0;
}

int mlx_accel_write_i2c(struct mlx5_core_dev *dev,
			size_t size, u64 addr, u8 *buf)
{
	u8 actual_size;
	size_t bytes_done = 0;
	size_t max_size = MLX5_FPGA_ACCESS_REG_SIZE_MAX;
	int rc;

	while (bytes_done < size) {
		actual_size = min(max_size, (size - bytes_done));

		rc = mlx5_fpga_access_reg(dev, actual_size,
					  addr + bytes_done,
					  buf + bytes_done, true);
		if (rc) {
			pr_err("Failed to write FPGA crspace data for %s\n",
			       dev_name(&dev->pdev->dev));
			return rc;
		}

		bytes_done += actual_size;
	}

	return 0;
}

#ifdef QP_SIMULATOR

static ssize_t core_conn_ip_read(struct mlx_accel_core_device *dev, char *buf)
{
	__be16 *sgid = (__be16 *)&dev->core_conn->fpga_qpc.remote_ip;

	return sprintf(buf, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n",
			be16_to_cpu(sgid[0]),
			be16_to_cpu(sgid[1]),
			be16_to_cpu(sgid[2]),
			be16_to_cpu(sgid[3]),
			be16_to_cpu(sgid[4]),
			be16_to_cpu(sgid[5]),
			be16_to_cpu(sgid[6]),
			be16_to_cpu(sgid[7]));
}

static ssize_t core_conn_qpn_read(struct mlx_accel_core_device *dev, char *buf)
{
	if (dev->core_conn && dev->core_conn->qp)
		return sprintf(buf, "%u\n", dev->core_conn->qp->qp_num);
	return sprintf(buf, "null\n");
}

static ssize_t core_conn_fpga_ip_write(struct mlx_accel_core_device *dev,
				       const char *buf, size_t count)
{
	__be16 *gid = (__be16 *)&dev->core_conn->fpga_qpc.fpga_ip;
	int i = 0;

	if (sscanf(buf, "%04hx:%04hx:%04hx:%04hx:%04hx:%04hx:%04hx:%04hx\n",
		   &gid[0], &gid[1], &gid[2], &gid[3],
		   &gid[4], &gid[5], &gid[6], &gid[7]) != 8)
		return -EINVAL;

	for (i = 0; i < 8; i++)
		gid[i] = cpu_to_be16(gid[i]);
	return count;
}

static ssize_t core_conn_fpga_qpn_write(struct mlx_accel_core_device *dev,
					const char *buf, size_t count)
{
	if (sscanf(buf, "%u\n", &dev->core_conn->fpga_qpn) != 1)
		return -EINVAL;
	return count;
}

static ssize_t core_conn_fpga_conn_write(struct mlx_accel_core_device *dev,
					 const char *buf, size_t count)
{
	int err;

	err = mlx_accel_core_rdma_connect(dev->core_conn);
	if (err) {
		pr_err("Failed to connect core RC QP to FPGA QP: %d\n", err);
		return -EIO;
	}
	return count;
}

struct core_conn_attribute {
	struct attribute attr;
	ssize_t (*show)(struct mlx_accel_core_device *dev, char *buf);
	ssize_t (*store)(struct mlx_accel_core_device *dev, const char *buf,
			 size_t count);
};

#define CORE_CONN_ATTR_RO(_name, _show) \
	struct core_conn_attribute core_conn_attr_ ## _name = { \
			.attr = {.name = __stringify(_name), .mode = 0444}, \
			.show = _show, \
	}
#define CORE_CONN_ATTR_WO(_name, _store) \
	struct core_conn_attribute core_conn_attr_ ## _name = { \
			.attr = {.name = __stringify(_name), .mode = 0222}, \
			.store = _store, \
	}
#define to_dev(obj) container_of(kobj, struct mlx_accel_core_device, sim_kobj)
#define to_attr(_attr) container_of(attr, struct core_conn_attribute, attr)

static CORE_CONN_ATTR_RO(ip, core_conn_ip_read);
static CORE_CONN_ATTR_RO(qpn, core_conn_qpn_read);
static CORE_CONN_ATTR_WO(fpga_qpn, core_conn_fpga_qpn_write);
static CORE_CONN_ATTR_WO(fpga_ip, core_conn_fpga_ip_write);
static CORE_CONN_ATTR_WO(fpga_conn, core_conn_fpga_conn_write);

struct attribute *core_conn_def_attrs[] = {
		&core_conn_attr_ip.attr,
		&core_conn_attr_qpn.attr,
		&core_conn_attr_fpga_ip.attr,
		&core_conn_attr_fpga_qpn.attr,
		&core_conn_attr_fpga_conn.attr,
		NULL,
};

static ssize_t core_conn_sysfs_show(struct kobject *kobj,
				    struct attribute *attr, char *buf)
{
	struct mlx_accel_core_device *dev = to_dev(kobj);
	struct core_conn_attribute *core_conn_attr = to_attr(attr);
	ssize_t ret = -EIO;

	if (core_conn_attr->show)
		ret = core_conn_attr->show(dev, buf);

	return ret;
}

static ssize_t core_conn_sysfs_store(struct kobject *kobj,
				     struct attribute *attr,
				     const char *buf, size_t count)
{
	struct mlx_accel_core_device *dev = to_dev(kobj);
	struct core_conn_attribute *core_conn_attr = to_attr(attr);
	ssize_t ret = -EIO;

	if (core_conn_attr->store)
		ret = core_conn_attr->store(dev, buf, count);

	return ret;
}

const struct sysfs_ops core_conn_sysfs_ops = {
	.show  = core_conn_sysfs_show,
	.store = core_conn_sysfs_store,
};

static struct kobj_type core_conn_sysfs_type = {
	.sysfs_ops      = &core_conn_sysfs_ops,
	.default_attrs  = core_conn_def_attrs,
};

int mlx_accel_fpga_qp_device_init(struct mlx_accel_core_device *accel_device)
{
	return kobject_init_and_add(&accel_device->sim_kobj,
				    &core_conn_sysfs_type,
				    mlx_accel_core_kobj(accel_device), "%s",
				    "fpga_core_conn");
}

int mlx_accel_fpga_qp_device_deinit(struct mlx_accel_core_device *accel_device)
{
	kobject_put(&accel_device->sim_kobj);
	return 0;
}

int mlx5_fpga_create_qp(struct mlx5_core_dev *dev,
			struct mlx5_fpga_qpc *fpga_qpc, u32 *fpga_qpn)
{
	return 0;
}

int mlx5_fpga_modify_qp(struct mlx5_core_dev *dev, u32 fpga_qpn,
			enum mlx5_fpga_qpc_field_select fields,
			struct mlx5_fpga_qpc *fpga_qpc)
{
	return 0;
}

int mlx5_fpga_destroy_qp(struct mlx5_core_dev *dev, u32 fpga_qpn)
{
	return 0;
}
#endif
