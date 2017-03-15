/*
 * Copyright (c) 2013-2015, Mellanox Technologies. All rights reserved.
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

#include "fpga.h"
#include <linux/etherdevice.h>

#if !IS_ENABLED(CONFIG_MLX5_CORE_FPGA_QP_SIM)
static void fpga_qpc_to_mailbox(struct mlx5_fpga_qpc *fpga_qpc, u8 *in)
{
	u8 *dst;

	MLX5_SET(fpga_qpc, in, state, fpga_qpc->state);
	MLX5_SET(fpga_qpc, in, qp_type, fpga_qpc->qp_type);
	MLX5_SET(fpga_qpc, in, st, fpga_qpc->st);
	MLX5_SET(fpga_qpc, in, traffic_class, fpga_qpc->tclass);
	MLX5_SET(fpga_qpc, in, ether_type, fpga_qpc->ether_type);
	MLX5_SET(fpga_qpc, in, prio, fpga_qpc->pcp);
	MLX5_SET(fpga_qpc, in, dei, fpga_qpc->dei);
	MLX5_SET(fpga_qpc, in, vid, fpga_qpc->vlan_id);
	MLX5_SET(fpga_qpc, in, next_rcv_psn, fpga_qpc->next_rcv_psn);
	MLX5_SET(fpga_qpc, in, next_send_psn, fpga_qpc->next_send_psn);
	MLX5_SET(fpga_qpc, in, pkey, fpga_qpc->pkey);
	MLX5_SET(fpga_qpc, in, remote_qpn, fpga_qpc->remote_qpn);
	MLX5_SET(fpga_qpc, in, rnr_retry, fpga_qpc->rnr_retry);
	MLX5_SET(fpga_qpc, in, retry_count, fpga_qpc->retry_count);

	dst = MLX5_ADDR_OF(fpga_qpc, in, remote_mac_47_32);
	ether_addr_copy(dst, fpga_qpc->remote_mac);
	dst = MLX5_ADDR_OF(fpga_qpc, in, remote_ip);
	memcpy(dst, &fpga_qpc->remote_ip, sizeof(struct in6_addr));
	dst = MLX5_ADDR_OF(fpga_qpc, in, fpga_mac_47_32);
	ether_addr_copy(dst, fpga_qpc->fpga_mac);
	dst = MLX5_ADDR_OF(fpga_qpc, in, fpga_ip);
	memcpy(dst, &fpga_qpc->fpga_ip, sizeof(struct in6_addr));
}

static void fpga_qpc_from_mailbox(struct mlx5_fpga_qpc *fpga_qpc, u8 *out)
{
	u8 *src;

	fpga_qpc->state = MLX5_GET(fpga_qpc, out, state);
	fpga_qpc->qp_type = MLX5_GET(fpga_qpc, out, qp_type);
	fpga_qpc->st = MLX5_GET(fpga_qpc, out, st);
	fpga_qpc->tclass = MLX5_GET(fpga_qpc, out, traffic_class);
	fpga_qpc->ether_type = MLX5_GET(fpga_qpc, out, ether_type);
	fpga_qpc->pcp = MLX5_GET(fpga_qpc, out, prio);
	fpga_qpc->dei = MLX5_GET(fpga_qpc, out, dei);
	fpga_qpc->vlan_id = MLX5_GET(fpga_qpc, out, vid);
	fpga_qpc->next_rcv_psn = MLX5_GET(fpga_qpc, out, next_rcv_psn);
	fpga_qpc->next_send_psn = MLX5_GET(fpga_qpc, out, next_send_psn);
	fpga_qpc->pkey = MLX5_GET(fpga_qpc, out, pkey);
	fpga_qpc->remote_qpn = MLX5_GET(fpga_qpc, out, remote_qpn);
	fpga_qpc->rnr_retry = MLX5_GET(fpga_qpc, out, rnr_retry);
	fpga_qpc->retry_count = MLX5_GET(fpga_qpc, out, retry_count);

	src = MLX5_ADDR_OF(fpga_qpc, out, remote_mac_47_32);
	ether_addr_copy(fpga_qpc->remote_mac, src);
	src = MLX5_ADDR_OF(fpga_qpc, out, remote_ip);
	memcpy(&fpga_qpc->remote_ip, src, sizeof(struct in6_addr));
	src = MLX5_ADDR_OF(fpga_qpc, out, fpga_mac_47_32);
	ether_addr_copy(fpga_qpc->fpga_mac, src);
	src = MLX5_ADDR_OF(fpga_qpc, out, fpga_ip);
	memcpy(&fpga_qpc->fpga_ip, src, sizeof(struct in6_addr));
}
#endif

int mlx5_fpga_create_qp(struct mlx5_core_dev *dev,
			struct mlx5_fpga_qpc *fpga_qpc, u32 *fpga_qpn)
{
#if IS_ENABLED(CONFIG_MLX5_CORE_FPGA_QP_SIM)
	return -EPERM;
#else
	int ret;
	u32 in[MLX5_ST_SZ_DW(fpga_create_qp_in)];
	u32 out[MLX5_ST_SZ_DW(fpga_create_qp_out)];

	memset(in, 0, sizeof(in));
	MLX5_SET(fpga_create_qp_in, in, opcode, MLX5_CMD_OP_FPGA_CREATE_QP);
	fpga_qpc_to_mailbox(fpga_qpc,
			    MLX5_ADDR_OF(fpga_create_qp_in, in, fpga_qpc));

	ret = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
	if (ret)
		goto out;

	fpga_qpc_from_mailbox(fpga_qpc,
			      MLX5_ADDR_OF(fpga_create_qp_out, out, fpga_qpc));
	*fpga_qpn = MLX5_GET(fpga_create_qp_out, out, fpga_qpn);
out:
	return ret;
#endif
}

int mlx5_fpga_modify_qp(struct mlx5_core_dev *dev, u32 fpga_qpn,
			enum mlx5_fpga_qpc_field_select fields,
			struct mlx5_fpga_qpc *fpga_qpc)
{
#if IS_ENABLED(CONFIG_MLX5_CORE_FPGA_QP_SIM)
	return -EPERM;
#else
	u32 in[MLX5_ST_SZ_DW(fpga_modify_qp_in)];
	u32 out[MLX5_ST_SZ_DW(fpga_modify_qp_out)];

	memset(in, 0, sizeof(in));
	MLX5_SET(fpga_modify_qp_in, in, opcode, MLX5_CMD_OP_FPGA_MODIFY_QP);
	MLX5_SET(fpga_modify_qp_in, in, field_select, fields);
	MLX5_SET(fpga_modify_qp_in, in, fpga_qpn, fpga_qpn);
	fpga_qpc_to_mailbox(fpga_qpc,
			    MLX5_ADDR_OF(fpga_modify_qp_in, in, fpga_qpc));

	return mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
#endif
}

int mlx5_fpga_query_qp(struct mlx5_core_dev *dev,
		       u32 fpga_qpn, struct mlx5_fpga_qpc *fpga_qpc)
{
#if IS_ENABLED(CONFIG_MLX5_CORE_FPGA_QP_SIM)
	return -EPERM;
#else
	int ret;
	u32 in[MLX5_ST_SZ_DW(fpga_query_qp_in)];
	u32 out[MLX5_ST_SZ_DW(fpga_query_qp_out)];

	memset(in, 0, sizeof(in));
	MLX5_SET(fpga_query_qp_in, in, opcode, MLX5_CMD_OP_FPGA_QUERY_QP);
	MLX5_SET(fpga_query_qp_in, in, fpga_qpn, fpga_qpn);

	ret = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
	if (ret)
		goto out;

	fpga_qpc_from_mailbox(fpga_qpc,
			      MLX5_ADDR_OF(fpga_query_qp_out, out, fpga_qpc));
out:
	return ret;
#endif
}

int mlx5_fpga_destroy_qp(struct mlx5_core_dev *dev, u32 fpga_qpn)
{
#if IS_ENABLED(CONFIG_MLX5_CORE_FPGA_QP_SIM)
	return -EPERM;
#else
	u32 in[MLX5_ST_SZ_DW(fpga_destroy_qp_in)];
	u32 out[MLX5_ST_SZ_DW(fpga_destroy_qp_out)];

	memset(in, 0, sizeof(in));
	MLX5_SET(fpga_destroy_qp_in, in, opcode, MLX5_CMD_OP_FPGA_DESTROY_QP);
	MLX5_SET(fpga_destroy_qp_in, in, fpga_qpn, fpga_qpn);

	return mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
#endif
}

int mlx5_fpga_query_qp_counters(struct mlx5_core_dev *dev, u32 fpga_qpn,
				bool clear, struct mlx5_fpga_qp_counters *data)
{
#if IS_ENABLED(CONFIG_MLX5_CORE_FPGA_QP_SIM)
	return -EPERM;
#else
	int ret;
	u32 in[MLX5_ST_SZ_DW(fpga_query_qp_counters_in)];
	u32 out[MLX5_ST_SZ_DW(fpga_query_qp_counters_out)];

	memset(in, 0, sizeof(in));
	MLX5_SET(fpga_query_qp_counters_in, in, opcode,
		 MLX5_CMD_OP_FPGA_QUERY_QP_COUNTERS);
	MLX5_SET(fpga_query_qp_counters_in, in, clear, clear);
	MLX5_SET(fpga_query_qp_counters_in, in, fpga_qpn, fpga_qpn);

	ret = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
	if (ret)
		goto out;

	data->rx_ack_packets = MLX5_GET64(fpga_query_qp_counters_out, out,
					  rx_ack_packets);
	data->rx_send_packets = MLX5_GET64(fpga_query_qp_counters_out, out,
					   rx_send_packets);
	data->tx_ack_packets = MLX5_GET64(fpga_query_qp_counters_out, out,
					  tx_ack_packets);
	data->tx_send_packets = MLX5_GET64(fpga_query_qp_counters_out, out,
					   tx_send_packets);
	data->rx_total_drop = MLX5_GET64(fpga_query_qp_counters_out, out,
					 rx_total_drop);

out:
	return ret;
#endif
}

int mlx5_fpga_shell_counters(struct mlx5_core_dev *dev, bool clear,
			     struct mlx5_fpga_shell_counters *data)
{
#if IS_ENABLED(CONFIG_MLX5_CORE_FPGA_QP_SIM)
	return -EPERM;
#else
	u32 in[MLX5_ST_SZ_DW(fpga_shell_counters)];
	u32 out[MLX5_ST_SZ_DW(fpga_shell_counters)];
	int err;

	memset(in, 0, sizeof(in));
	MLX5_SET(fpga_shell_counters, in, clear, clear);
	err = mlx5_core_access_reg(dev, in, sizeof(in), out, sizeof(out),
				   MLX5_REG_FPGA_SHELL_CNTR, 0, false);
	if (err)
		goto out;
	if (data) {
		data->ddr_read_requests = MLX5_GET64(fpga_shell_counters, out,
						     ddr_read_requests);
		data->ddr_write_requests = MLX5_GET64(fpga_shell_counters, out,
						      ddr_write_requests);
		data->ddr_read_bytes = MLX5_GET64(fpga_shell_counters, out,
						  ddr_read_bytes);
		data->ddr_write_bytes = MLX5_GET64(fpga_shell_counters, out,
						   ddr_write_bytes);
	}

out:
	return err;
#endif
}
