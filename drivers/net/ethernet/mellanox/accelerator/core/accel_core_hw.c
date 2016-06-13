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

#ifdef WORKAROUND_I2C

#define GW_CTRL_ADDR_SHIFT 26
#define GW_CTRL_RW   BIT(29)
#define GW_CTRL_BUSY BIT(30)
#define GW_CTRL_LOCK BIT(31)

static int mlx_accel_gw_waitfor(struct mlx5_core_dev *dev, u64 addr, u32 mask,
				u32 value)
{
	int ret = 0;
	u32 gw_value;
	int try = 0;
	static const int max_tries = 100;

	while (true) {
		pr_debug("Waiting for %x/%x. Try %d\n", value, mask, try);
		ret = mlx_accel_read_i2c(dev, sizeof(u32), addr,
					 (u8 *)&gw_value);
		if (ret)
			return ret;
		gw_value = ntohl(gw_value);
		pr_debug("Value is %x\n", gw_value);
		if ((gw_value & mask) == value)
			break;
		try++;
		if (try >= max_tries) {
			pr_debug("Timeout waiting for %x/%x at %llx. Value is %x after %d tries\n",
				 value, mask, addr, gw_value, try);
			return -EBUSY;
		}
		usleep_range(10, 100);
	};
	return 0;
}

static int mlx_accel_gw_lock(struct mlx5_core_dev *dev, u64 addr)
{
	return mlx_accel_gw_waitfor(dev, addr, GW_CTRL_LOCK, 0);
}

static int mlx_accel_gw_unlock(struct mlx5_core_dev *dev, u64 addr)
{
	u32 gw_value;
	int ret;

	pr_debug("Unlocking %llx\n", addr);
	ret = mlx_accel_read_i2c(dev, sizeof(u32), addr, (u8 *)&gw_value);
	if (ret)
		return ret;
	gw_value = ntohl(gw_value);
	if ((gw_value & GW_CTRL_LOCK) != GW_CTRL_LOCK)
		pr_warn("Lock expected when unlocking, but not held for device %s addr %llx\n",
			dev->priv.name, addr);

	pr_debug("Old value %x\n", gw_value);
	gw_value &= ~GW_CTRL_LOCK;
	pr_debug("New value %x\n", gw_value);
	gw_value = htonl(gw_value);
	ret = mlx_accel_write_i2c(dev, sizeof(u32), addr, (u8 *)&gw_value);
	if (ret)
		return ret;
	return 0;
}

static int mlx_accel_gw_op(struct mlx5_core_dev *dev, u64 addr,
			   unsigned int index, bool write)
{
	u32 gw_value;
	int ret;

	if (index >= 8)
		pr_warn("Trying to access index %u out of range for GW at %llx\n",
			index, addr);

	pr_debug("Performing op %u at %llx\n", write, addr);
	ret = mlx_accel_read_i2c(dev, sizeof(u32), addr, (u8 *)&gw_value);
	if (ret)
		return ret;
	gw_value = ntohl(gw_value);
	pr_debug("Old op value is %x\n", gw_value);
	if ((gw_value & GW_CTRL_LOCK) != GW_CTRL_LOCK)
		pr_warn("Lock expected for %s, but not held for device %s addr %llx\n",
			write ? "write" : "read", dev->priv.name, addr);

	gw_value &= ~(7 << GW_CTRL_ADDR_SHIFT);
	gw_value |= index << GW_CTRL_ADDR_SHIFT;

	if (write)
		gw_value &= ~GW_CTRL_RW;
	else
		gw_value |= GW_CTRL_RW;

	gw_value |= GW_CTRL_BUSY;

	pr_debug("New op value is %x\n", gw_value);
	gw_value = htonl(gw_value);
	ret = mlx_accel_write_i2c(dev, sizeof(u32), addr, (u8 *)&gw_value);
	if (ret)
		return ret;

	return mlx_accel_gw_waitfor(dev, addr, GW_CTRL_BUSY, 0);
}

static int mlx_accel_gw_read(struct mlx5_core_dev *dev, u64 addr,
			     unsigned int index)
{
	return mlx_accel_gw_op(dev, addr, index, false);
}

static int mlx_accel_gw_write(struct mlx5_core_dev *dev, u64 addr,
			      unsigned int index)
{
	return mlx_accel_gw_op(dev, addr, index, true);
}

enum ack_type {
	ACK_TYPE_NONE = 0,
	ACK_TYPE_ACK = 1,
	ACK_TYPE_RNRNAK = 2,
	ACK_TYPE_INVNAK = 3,
	ACK_TYPE_PSNNAK = 4,
};

static int mlx_accel_qpc_write(struct mlx5_core_dev *dev,
			       unsigned int qpc_index,
			       u64 base, __be16 mac_high, __be32 mac_low,
			       u16 pkey, u32 qpn, bool req_drop, bool res_drop,
			       u32 peer_qpn, u8 tclass, u32 app,
			       u32 vlan_header, __be32 *ip)
{
	int ret;
	u32 value;

	ret = mlx_accel_gw_lock(dev, base);
	if (ret) {
		pr_warn("Failed to lock QPC GW in %s\n", dev->priv.name);
		goto out;
	}
	value = htonl(pkey << 16 | ntohs(mac_high));
	ret = mlx_accel_write_i2c(dev, sizeof(u32), base + 0x18, (u8 *)&value);
	if (ret) {
		pr_warn("Failed to write QPC\n");
		goto unlock;
	}
	value = mac_low;
	ret = mlx_accel_write_i2c(dev, sizeof(u32), base + 0x1c, (u8 *)&value);
	if (ret) {
		pr_warn("Failed to write QPC\n");
		goto unlock;
	}
	value = htonl(qpn | (req_drop << 24) | (res_drop << 25));
	ret = mlx_accel_write_i2c(dev, sizeof(u32), base + 0x20, (u8 *)&value);
	if (ret) {
		pr_warn("Failed to write QPC\n");
		goto unlock;
	}
	value = htonl(peer_qpn | ((u32)tclass << 24));
	ret = mlx_accel_write_i2c(dev, sizeof(u32), base + 0x24, (u8 *)&value);
	if (ret) {
		pr_warn("Failed to write QPC\n");
		goto unlock;
	}
	value = htonl(app);
	ret = mlx_accel_write_i2c(dev, sizeof(u32), base + 0x28, (u8 *)&value);
	if (ret) {
		pr_warn("Failed to write QPC\n");
		goto unlock;
	}
	value = htonl(vlan_header);
	ret = mlx_accel_write_i2c(dev, sizeof(u32), base + 0x2C, (u8 *)&value);
	if (ret) {
		pr_warn("Failed to write QPC\n");
		goto unlock;
	}
	value = ip[0];
	ret = mlx_accel_write_i2c(dev, sizeof(u32), base + 0x30, (u8 *)&value);
	if (ret) {
		pr_warn("Failed to write QPC\n");
		goto unlock;
	}
	value = ip[1];
	ret = mlx_accel_write_i2c(dev, sizeof(u32), base + 0x34, (u8 *)&value);
	if (ret) {
		pr_warn("Failed to write QPC\n");
		goto unlock;
	}
	value = ip[2];
	ret = mlx_accel_write_i2c(dev, sizeof(u32), base + 0x38, (u8 *)&value);
	if (ret) {
		pr_warn("Failed to write QPC\n");
		goto unlock;
	}
	value = ip[3];
	ret = mlx_accel_write_i2c(dev, sizeof(u32), base + 0x3C, (u8 *)&value);
	if (ret) {
		pr_warn("Failed to write QPC\n");
		goto unlock;
	}
	ret = mlx_accel_gw_write(dev, base, qpc_index);
	if (ret) {
		pr_warn("Failed to write QPC #0 in %s\n", dev->priv.name);
		goto unlock;
	}
	goto unlock;

unlock:
	mlx_accel_gw_unlock(dev, base);
out:
	return ret;
}

static int mlx_accel_qpc_2_write(struct mlx5_core_dev *dev,
				 unsigned int qpc_index, u64 base,
				 u32 ona_psn, u32 req_state,
				 u32 exp_psn, enum ack_type ack_type,
				 u32 res_state)
{
	int ret;
	u32 value;

	ret = mlx_accel_gw_lock(dev, base + 0x40);
	if (ret) {
		pr_warn("Failed to lock QPC GW in %s\n", dev->priv.name);
		goto out;
	}
	value = htonl(ona_psn | (req_state << 24));
	ret = mlx_accel_write_i2c(dev, sizeof(u32), base + 0x48, (u8 *)&value);
	if (ret) {
		pr_warn("Failed to init QPC\n");
		goto unlock;
	}
	value = htonl(exp_psn | (ack_type << 24) | (res_state << 28));
	ret = mlx_accel_write_i2c(dev, sizeof(u32), base + 0x4c, (u8 *)&value);
	if (ret) {
		pr_warn("Failed to init QPC\n");
		goto unlock;
	}
	ret = mlx_accel_gw_write(dev, base + 0x40, qpc_index);
	if (ret) {
		pr_warn("Failed to write QPC #0 in %s\n", dev->priv.name);
		goto unlock;
	}

unlock:
	mlx_accel_gw_unlock(dev, base + 0x40);
out:
	return ret;
}

/* TODO: For image 274 and prior, base is 0x900600 */
/* TODO: For image 322 and later, base is 0x950000 */
#define FPGA_TCA_QP_BASE 0x950000
#define SX_PACKET_RESOLUTION_IP 0x948000
#define SX_PACKET_RESOLUTION_MY_PORT 0x948018
#define SX_PACKET_RESOLUTION_PEER_PORT 0x948020
/* TODO: For image 322 and prior, flush_qp_buf is 0x94a000 */
/* TODO: For image 471 and later, flush_qp_buf is 0x948800 */
#define SX_CONTROL_FLUSH_QP_BUF 0x948800
static const u32 fpga_ip[4] = {0xfe800000, 0, 0xf65214ff, 0xfe000000};
static const u8 fpga_mac[ETH_ALEN] = {0xf4, 0x52, 0x14, 0, 0, 0};

int mlx_accel_fpga_qp_device_init(struct mlx_accel_core_device *accel_device)
{
	int ret;
	u32 value;

	value = htonl(fpga_ip[0]);
	ret = mlx_accel_write_i2c(accel_device->hw_dev, sizeof(u32),
				  SX_PACKET_RESOLUTION_IP, (u8 *)&value);
	if (ret)
		return ret;
	value = htonl(fpga_ip[1]);
	ret = mlx_accel_write_i2c(accel_device->hw_dev, sizeof(u32),
				  SX_PACKET_RESOLUTION_IP + 4, (u8 *)&value);
	if (ret)
		return ret;
	value = htonl(fpga_ip[2]);
	ret = mlx_accel_write_i2c(accel_device->hw_dev, sizeof(u32),
				  SX_PACKET_RESOLUTION_IP + 8, (u8 *)&value);
	if (ret)
		return ret;
	value = htonl(fpga_ip[3]);
	ret = mlx_accel_write_i2c(accel_device->hw_dev, sizeof(u32),
				  SX_PACKET_RESOLUTION_IP + 12, (u8 *)&value);
	if (ret)
		return ret;
	value = htonl(0xc000);
	ret = mlx_accel_write_i2c(accel_device->hw_dev, sizeof(u32),
				  SX_PACKET_RESOLUTION_MY_PORT, (u8 *)&value);
	if (ret)
		return ret;
	value = htonl(ROCE_V2_UDP_DPORT);
	ret = mlx_accel_write_i2c(accel_device->hw_dev, sizeof(u32),
				  SX_PACKET_RESOLUTION_PEER_PORT, (u8 *)&value);
	if (ret)
		return ret;

	return 0;
}

int mlx5_fpga_create_qp(struct mlx5_core_dev *dev,
			struct mlx5_fpga_qpc *fpga_qpc, u32 *fpga_qpn)
{
	int ret;
	__be16 mac_high;
	__be32 mac_low;
	static int next_qpn;
	u32 qpn = next_qpn++;
	int qp_index = qpn & 7;
	u32 value;

	mac_high = *(__be16 *)&fpga_qpc->remote_mac[0];
	mac_low = *(__be32 *)(&fpga_qpc->remote_mac[2]);

	ret = mlx_accel_qpc_2_write(dev, qp_index, FPGA_TCA_QP_BASE,
				    fpga_qpc->next_rcv_psn, fpga_qpc->state,
				    fpga_qpc->next_send_psn, ACK_TYPE_ACK,
				    fpga_qpc->state);
	if (ret)
		goto out;

	value = htonl(1 << qp_index);
	ret = mlx_accel_write_i2c(dev, sizeof(u32),
				  SX_CONTROL_FLUSH_QP_BUF, (u8 *)&value);
	if (ret) {
		pr_warn("Failed to flush QP SX buffer\n");
		goto out;
	}

	ret = mlx_accel_qpc_write(dev, qp_index, FPGA_TCA_QP_BASE,
				  mac_high, mac_low, fpga_qpc->pkey, qpn & ~7,
				  false, false,
				  fpga_qpc->remote_qpn, fpga_qpc->tclass, 0,
				  ((u32)fpga_qpc->ether_type << 16) |
				  ((u32)fpga_qpc->pcp << 13) |
				  ((u32)fpga_qpc->dei << 12) |
				  (u32)fpga_qpc->vlan_id,
				  (__be32 *)&fpga_qpc->remote_ip);
	if (ret)
		goto out;

	*fpga_qpn = qpn;
	for (ret = 0; ret < 4; ret++)
		fpga_qpc->fpga_ip.s6_addr32[ret] = htonl(fpga_ip[ret]);

	memcpy(&fpga_qpc->fpga_mac, &fpga_mac, sizeof(fpga_qpc->fpga_mac));
	ret = 0;

out:
	return ret;
}

int mlx5_fpga_modify_qp(struct mlx5_core_dev *dev, u32 fpga_qpn,
			enum mlx5_fpga_qpc_field_select fields,
			struct mlx5_fpga_qpc *fpga_qpc)
{
	int ret;
	int qp_index = fpga_qpn & 7;
	u32 value;

	ret = mlx_accel_qpc_2_write(dev, qp_index, FPGA_TCA_QP_BASE,
				    fpga_qpc->next_rcv_psn, fpga_qpc->state,
				    fpga_qpc->next_send_psn, ACK_TYPE_ACK,
				    fpga_qpc->state);
	if (ret)
		goto out;

	value = htonl(1 << qp_index);
	ret = mlx_accel_write_i2c(dev, sizeof(u32),
				  SX_CONTROL_FLUSH_QP_BUF, (u8 *)&value);
	if (ret) {
		pr_warn("Failed to flush QP SX buffer\n");
		goto out;
	}

	ret = 0;

out:
	return ret;
}

int mlx5_fpga_destroy_qp(struct mlx5_core_dev *dev, u32 fpga_qpn)
{
	int qp_index = fpga_qpn & 7;

	return mlx_accel_qpc_2_write(dev, qp_index, FPGA_TCA_QP_BASE,
				     0, MLX5_FPGA_QP_STATE_INIT, 0,
				     ACK_TYPE_ACK, MLX5_FPGA_QP_STATE_INIT);
}

#endif /* WORKAROUND_I2C */
