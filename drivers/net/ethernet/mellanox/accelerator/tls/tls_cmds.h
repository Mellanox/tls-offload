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

#ifndef MLX_TLS_CMDS_H
#define MLX_TLS_CMDS_H

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

struct tls_cntx_tcp {
	__be32 ip_da[4];
	__be32 flags;
	__be16 src_port;
	__be16 dst_port;
	__be32 sw_sa_id;
	__be32 tcp_sn;
	__be32 ip_sa[4];
} __packed;

struct tls_cntx_crypto {
	u8 enc_state[16];
	u8 enc_key[32];
} __packed;

struct tls_cntx_record {
	u8 rcd_sn[8];
	u16 pad;
	u8 flags;
	u8 rcd_type_ver;
	__be32 rcd_tcp_sn_nxt;
	__be32 rcd_implicit_iv;
	u8 rcd_residue[32];
} __packed;

#define TLS_RCD_ENC_AES_GCM128	(0)
#define TLS_RCD_ENC_AES_GCM256	(BIT(4))
#define TLS_RCD_AUTH_AES_GCM128	(0)
#define TLS_RCD_AUTH_AES_GCM256	(1)

#define TLS_RCD_VER_1_2		(3)

struct tls_cntx {
	struct tls_cntx_tcp	tcp;
	struct tls_cntx_record	rcd;
	struct tls_cntx_crypto	crypto;
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

#endif /* MLX_TLS_CMDS_H */
