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

#ifndef MLX_IPSEC_CMDS_H
#define MLX_IPSEC_CMDS_H


#define UNASSIGNED_SA_ID ((u32)~0)

enum rcv_pet_syndrome {
	/*PET_SYNDROME_DECRYPTED_WITH_DUMMY_IP	= 0x00,*/
	PET_SYNDROME_DECRYPTED			= 0x01,
	PET_SYNDROME_AUTH_FAILED		= 0x02
};

struct rcv_pet_content {
	unsigned char   reserved;
	__be32		sa_id;
} __packed;

enum send_pet_syndrome {
	PET_SYNDROME_OFFLOAD_REQUIRED		= 0,
	PET_SYNDROME_OFFLOAD_WITH_LSO_REQUIRED	= 1
};

struct send_pet_content {
	/* The next two fields are meaningful only when LSO adjustments are
	 * enabled (by the syndrome field))
	 */
	__be16 mss_inverse;	/* 1/MSS in 16bit fixed point */
	__be16 seq;		/* LSBs of the first TCP seq in the packet */
	unsigned char reserved;
} __packed;

struct pet {
	unsigned char	syndrome;
	union {
		unsigned char	raw[5];
		/* from FPGA to host, on successful decrypt */
		struct rcv_pet_content rcv;
		/* from host to FPGA */
		struct send_pet_content send;
	} __packed content;
	__be16		ethertype;		/* packet type ID field	*/
} __packed;

#define IPPROTO_DUMMY_DWORD 0xff

struct dummy_dword {
	unsigned char next_proto;
	unsigned char len;
	__be16 reserved;
} __packed;

enum fpga_cmds {
	CMD_ADD_SA			= 1,
	CMD_UPDATE_SA			= 2,
	CMD_DEL_SA			= 3
};

enum fpga_del_sa_status {
	DEL_SA_SUCCESS			= 0x80,
	DEL_SA_FAIL_NOT_FOUND		= 0x81
};

/* [BP]: TODO - Test all return codes in mlx_xfrm_add_state */
enum fpga_add_sa_status {
	ADD_SA_PENDING			= -1,
	ADD_SA_SUCCESS			= 0,
	ADD_SA_FAIL_CAPACITY		= 1,
	ADD_SA_FAIL_CONFLICT		= 2
};

enum fpga_response {
	EVENT_ADD_SA_RESPONSE			= 0x81,
	EVENT_ADD_SA_ERR_RESPONSE		= 0xC1,
	EVENT_UPDATE_SA_RESPONSE		= 0x82,
	EVENT_UPDATE_SA_ERR_RESPONSE		= 0xC2,
	EVENT_DEL_SA_RESPONSE			= 0x83,
	EVENT_DEL_SA_ERR_RESPONSE		= 0xC3
};

enum direction {
	RX_DIRECTION = 0,
	TX_DIRECTION = 1
};

enum crypto_identifier {
	IPSEC_OFFLOAD_CRYPTO_NONE	 = 0,
	IPSEC_OFFLOAD_CRYPTO_AES_GCM_128 = 1,
	IPSEC_OFFLOAD_CRYPTO_AES_GCM_256 = 2,
};

enum auth_identifier {
	IPSEC_OFFLOAD_AUTH_NONE	       = 0,
	IPSEC_OFFLOAD_AUTH_AES_GCM_128 = 1,
	IPSEC_OFFLOAD_AUTH_AES_GCM_256 = 2,
};

/* [BP]: TODO - There should be another command for IPv6 */
struct sa_cmd_v4 {
	__be32 cmd;
	u8 key[32];
	__be32 sip;
	__be32 sip_mask; /* must be 255.255.255.255 */
	__be32 dip;
	__be32 dip_mask; /* must be 255.255.255.255 */
	__be32 spi;
	__be32 salt;
	__be32 sw_sa_handle;
	__be16 sport; /* unused */
	__be16 dport; /* unused */
	u8 ip_proto;
	u8 enc_auth_mode;
	u8 enable;
	u8 pad;
};

#define SADB_DIR_SX      BIT(7)
#define SADB_SA_VALID    BIT(6)
#define SADB_SPI_EN      BIT(5)
#define SADB_IP_PROTO_EN BIT(4)
#define SADB_SPORT_EN    BIT(3)
#define SADB_DPORT_EN    BIT(2)
#define SADB_TUNNEL      BIT(1)
#define SADB_TUNNEL_EN   BIT(0)

struct fpga_reply_generic {
	__be32 opcode;
	__be32 sw_sa_id;
	__be32 hw_sa_id;
};

struct fpga_reply_add_sa {
	struct fpga_reply_generic generic;
	__be32 status;
};

#endif /* MLX_IPSEC_CMDS_H */
