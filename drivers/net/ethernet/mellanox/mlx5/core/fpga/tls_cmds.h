/*
 * Copyright (c) 2017 Mellanox Technologies. All rights reserved.
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

#ifndef __MLX5_FPGA_TLS_CMDS_H__
#define __MLX5_FPGA_TLS_CMDS_H__

#define MLX_TLS_SADB_RDMA

enum fpga_cmds {
	CMD_SETUP_STREAM		= 1,
	CMD_TEARDOWN_STREAM		= 2,
};

enum fpga_response {
	EVENT_SETUP_STREAM_RESPONSE	= 0x81,
};

#define TLS_TCP_IP_PROTO   BIT(3)	/* 0 - UDP; 1 - TCP */
#define TLS_TCP_INIT       BIT(2)	/* 1 - Initialized */
#define TLS_TCP_VALID      BIT(1)	/* 1 - Valid */
#define TLS_TCP_IPV6       BIT(0)	/* 0 - IPv4;1 - IPv6 */

struct mlx5_ifc_tls_cntx_tcp_bits {
	u8         ip_da_127_96[0x20];

	u8         ip_da_95_64[0x20];

	u8         ip_da_63_32[0x20];

	u8         ip_da_31_0[0x20];

	u8         reserved_at_80[0x1e];
	u8         sa_vld[0x1];
	u8         ip_ver[0x1];

	u8         src_port[0x10];
	u8         dst_port[0x10];

	u8         ip_sa_127_96[0x20];

	u8         ip_sa_95_64[0x20];

	u8         ip_sa_63_32[0x20];

	u8         ip_sa_31_0[0x20];

};

#define TLS_RCD_ENC_AES_GCM128	(0)
#define TLS_RCD_ENC_AES_GCM256	(BIT(4))
#define TLS_RCD_AUTH_AES_GCM128	(0)
#define TLS_RCD_AUTH_AES_GCM256	(1)

#define TLS_RCD_VER_1_2		(3)

struct mlx5_ifc_tls_cntx_rcd_bits {
	u8         iv_offset_63_32[0x20];

	u8         iv_offset_31_0[0x20];

	u8         rcd_sn_63_32[0x20];

	u8         rcd_sn_31_0[0x20];

	u8         rcd_residue_127_96[0x20];

	u8         rcd_residue_95_64[0x20];

	u8         rcd_residue_63_32[0x20];

	u8         rcd_residue_31_0[0x20];

	u8         reserved_at_100[0x1a];
	u8         chng_cipherspec_det[0x1];
	u8         tcp_init_flag[0x1];
	u8         rcd_sync[0x1];
	u8         rcd_bypass[0x1];
	u8         state[0x2];

	u8         rcd_ver[0x4];
	u8         rcd_hdr_position[0x4];
	u8         rcd_type[0x4];
	u8         iv_offset_op[0x4];
	u8         reserved_at_130[0x2];
	u8         magic_residue[0x6];
	u8         crypto_mode[0x8];

	u8         tcp_sync_sn[0x20];

	u8         rcd_implicit_iv[0x20];

	u8         rcd_tcp_sn_nxt[0x20];

	u8         tcp_sn[0x20];

	u8         crypto_key_255_224[0x20];

	u8         crypto_key_223_192[0x20];

	u8         crypto_key_191_160[0x20];

	u8         crypto_key_159_128[0x20];

	u8         crypto_key_127_96[0x20];

	u8         crypto_key_95_64[0x20];

	u8         crypto_key_63_32[0x20];

	u8         crypto_key_31_0[0x20];
};


struct tls_cntx {
	u8 ctx[MLX5_ST_SZ_BYTES(tls_cntx_tcp) + MLX5_ST_SZ_BYTES(tls_cntx_rcd)];
} __packed;

struct setup_stream_cmd {
	u8 cmd;
	__be32 stream_id;
	struct tls_cntx tls;
} __packed;

struct teardown_stream_cmd {
	u8 cmd;
	__be32 stream_id;
} __packed;

struct generic_event {
	__be32 opcode;
	__be32 stream_id;
};

struct setup_stream_response {
	__be32 opcode;
	__be32 stream_id;
};

#endif /* __MLX5_FPGA_TLS_CMDS_H__ */
