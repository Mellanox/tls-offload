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
#include <linux/mlx5/accel_sdk.h>
#include "fpga.h"

struct accel_attribute {
	struct attribute attr;
	ssize_t (*show)(struct mlx_accel_core_device *, char *);
	ssize_t (*store)(struct mlx_accel_core_device *, const char *, size_t);
};

#define ACCEL_ATTR_RW(_name) \
struct accel_attribute accel_attr_##_name = __ATTR_RW(_name)

#define ACCEL_ATTR_RO(_name) \
struct accel_attribute accel_attr_##_name = __ATTR_RO(_name)

#define ACCEL_ATTR_WO(_name) \
struct accel_attribute accel_attr_##_name = __ATTR_WO(_name)

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

static ssize_t fpga_caps_show(struct mlx_accel_core_device *device, char *buf)
{
	struct mlx5_core_dev *mdev = device->hw_dev;

	return scnprintf(buf, PAGE_SIZE,
			 "FPGA ID: 0x%02x\n"
			 "FPGA Device: 0x%06x\n"
			 "Register File Version: 0x%08x\n"
			 "FPGA Ctrl Modify: %u\n"
			 "Access Reg Query: %u\n"
			 "Access Reg Modify: %u\n"
			 "Image Version: 0x%08x\n"
			 "Image Date: 0x%08x\n"
			 "Image Time: 0x%08x\n"
			 "Shell Version: 0x%08x\n"
			 "IEEE Vendor ID: 0x%06x\n"
			 "SBU Product Version: 0x%04x\n"
			 "SBU Product ID: 0x%04x\n"
			 "SBU Basic Caps: 0x%08x\n"
			 "SBU Extended Caps Len: 0x%04x\n"
			 "SBU Extended Caps Address: 0x%llx\n"
			 "FPGA DDR Start Address: 0x%llx\n"
			 "FPGA CrSpace Start Address: 0x%llx\n"
			 "FPGA DDR Size: 0x%llx\n"
			 "FPGA CrSpace Size: 0x%llx\n",
			 MLX5_CAP_FPGA(mdev, fpga_id),
			 MLX5_CAP_FPGA(mdev, fpga_device),
			 MLX5_CAP_FPGA(mdev, register_file_ver),
			 MLX5_CAP_FPGA(mdev, fpga_ctrl_modify),
			 MLX5_CAP_FPGA(mdev, access_reg_query_mode),
			 MLX5_CAP_FPGA(mdev, access_reg_modify_mode),
			 MLX5_CAP_FPGA(mdev, image_version),
			 MLX5_CAP_FPGA(mdev, image_date),
			 MLX5_CAP_FPGA(mdev, image_time),
			 MLX5_CAP_FPGA(mdev, shell_version),
			 MLX5_CAP_FPGA(mdev, ieee_vendor_id),
			 MLX5_CAP_FPGA(mdev, sandbox_product_version),
			 MLX5_CAP_FPGA(mdev, sandbox_product_id),
			 MLX5_CAP_FPGA(mdev, sandbox_basic_caps),
			 MLX5_CAP_FPGA(mdev, sandbox_extended_caps_len),
			 MLX5_CAP64_FPGA(mdev, sandbox_extended_caps_addr),
			 MLX5_CAP64_FPGA(mdev, fpga_ddr_start_addr),
			 MLX5_CAP64_FPGA(mdev, fpga_cr_space_start_addr),
			 1024ULL * MLX5_CAP_FPGA(mdev, fpga_ddr_size),
			 1024ULL * MLX5_CAP_FPGA(mdev, fpga_cr_space_size));
}

static ssize_t shell_caps_show(struct mlx_accel_core_device *device, char *buf)
{
	struct mlx5_core_dev *mdev = device->hw_dev;

	return scnprintf(buf, PAGE_SIZE,
			 "Maximum Number of QPs: %u\n"
			 "Total Receive Credits: %u\n"
			 "QP Type: %u\n"
			 "RAE: %u\n"
			 "RWE: %u\n"
			 "RRE: %u\n"
			 "DC: %u\n"
			 "UD: %u\n"
			 "UC: %u\n"
			 "RC: %u\n"
			 "DDR Size: %u GB\n"
			 "QP Message Size: 0x%08x\n",
			 MLX5_CAP_FPGA(mdev, shell_caps.max_num_qps),
			 MLX5_CAP_FPGA(mdev, shell_caps.total_rcv_credits),
			 MLX5_CAP_FPGA(mdev, shell_caps.qp_type),
			 MLX5_CAP_FPGA(mdev, shell_caps.rae),
			 MLX5_CAP_FPGA(mdev, shell_caps.rwe),
			 MLX5_CAP_FPGA(mdev, shell_caps.rre),
			 MLX5_CAP_FPGA(mdev, shell_caps.dc),
			 MLX5_CAP_FPGA(mdev, shell_caps.ud),
			 MLX5_CAP_FPGA(mdev, shell_caps.uc),
			 MLX5_CAP_FPGA(mdev, shell_caps.rc),
			 1 << MLX5_CAP_FPGA(mdev, shell_caps.log_ddr_size),
			 MLX5_CAP_FPGA(mdev,
				       shell_caps.max_fpga_qp_msg_size));
}

static ssize_t shell_counters_show(struct mlx_accel_core_device *device,
				   char *buf)
{
	struct mlx5_fpga_shell_counters data;
	int ret = mlx5_fpga_shell_counters(device->hw_dev, false, &data);

	if (ret)
		return -EIO;
	return scnprintf(buf, PAGE_SIZE,
			 "DDR Read Requests: %llu\n"
			 "DDR Write Requests: %llu\n"
			 "DDR Read Bytes: %llu\n"
			 "DDR Write Bytes: %llu\n",
			 data.ddr_read_requests,
			 data.ddr_write_requests,
			 data.ddr_read_bytes,
			 data.ddr_write_bytes);
}

static ssize_t shell_counters_store(struct mlx_accel_core_device *device,
				    const char *buf, size_t size)
{
	int ret = mlx5_fpga_shell_counters(device->hw_dev, true, NULL);

	if (ret)
		return -EIO;
	return size;
}

ssize_t mlx_accel_counters_sysfs_store(struct mlx_accel_core_conn *conn,
				       const char *buf, size_t size)
{
	int ret = mlx5_fpga_query_qp_counters(conn->accel_device->hw_dev,
					      conn->fpga_qpn, true, NULL);

	if (ret)
		return -EIO;
	return size;
}
EXPORT_SYMBOL(mlx_accel_counters_sysfs_store);

ssize_t mlx_accel_counters_sysfs_show(struct mlx_accel_core_conn *conn,
				      char *buf)
{
	struct mlx5_fpga_qp_counters data;
	int ret = mlx5_fpga_query_qp_counters(conn->accel_device->hw_dev,
					      conn->fpga_qpn, false, &data);

	if (ret)
		return -EIO;
	return scnprintf(buf, PAGE_SIZE,
			 "RX Ack Packets: %llu\n"
			 "RX Send Packets: %llu\n"
			 "TX Ack Packets: %llu\n"
			 "TX Send Packets: %llu\n"
			 "RX Total Drop: %llu\n",
			 data.rx_ack_packets,
			 data.rx_send_packets,
			 data.tx_ack_packets,
			 data.tx_send_packets,
			 data.rx_total_drop);
}
EXPORT_SYMBOL(mlx_accel_counters_sysfs_show);

static ssize_t qp_counters_show(struct mlx_accel_core_device *device,
				char *buf)
{
	return mlx_accel_counters_sysfs_show(device->core_conn, buf);
}

static ssize_t qp_counters_store(struct mlx_accel_core_device *device,
				 const char *buf, size_t size)
{
	return mlx_accel_counters_sysfs_store(device->core_conn, buf, size);
}

static ACCEL_ATTR_RO(fpga_caps);
static ACCEL_ATTR_RO(shell_caps);
static ACCEL_ATTR_RW(shell_counters);
static ACCEL_ATTR_RW(qp_counters);

#ifdef QP_SIMULATOR

static ssize_t ip_show(struct mlx_accel_core_device *dev, char *buf)
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

static ssize_t qpn_show(struct mlx_accel_core_device *dev, char *buf)
{
	if (dev->core_conn && dev->core_conn->qp)
		return sprintf(buf, "%u\n", dev->core_conn->qp->qp_num);
	return sprintf(buf, "null\n");
}

static ssize_t fpga_ip_store(struct mlx_accel_core_device *dev, const char *buf,
			     size_t count)
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

static ssize_t fpga_qpn_store(struct mlx_accel_core_device *dev,
			      const char *buf, size_t count)
{
	if (sscanf(buf, "%u\n", &dev->core_conn->fpga_qpn) != 1)
		return -EINVAL;
	return count;
}

static ssize_t fpga_conn_store(struct mlx_accel_core_device *dev,
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

static ACCEL_ATTR_RO(ip);
static ACCEL_ATTR_RO(qpn);
static ACCEL_ATTR_WO(fpga_qpn);
static ACCEL_ATTR_WO(fpga_ip);
static ACCEL_ATTR_WO(fpga_conn);

#endif

static struct attribute *accel_default_attrs[] = {
	&accel_attr_fpga_caps.attr,
	&accel_attr_shell_caps.attr,
	&accel_attr_shell_counters.attr,
	&accel_attr_qp_counters.attr,
#ifdef QP_SIMULATOR
	&accel_attr_ip.attr,
	&accel_attr_qpn.attr,
	&accel_attr_fpga_ip.attr,
	&accel_attr_fpga_qpn.attr,
	&accel_attr_fpga_conn.attr,
#endif
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
