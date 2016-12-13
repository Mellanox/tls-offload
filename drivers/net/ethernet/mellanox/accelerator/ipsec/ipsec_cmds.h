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

enum rcv_pet_syndrom {
	/*PET_SYNDROME_DECRYPTED_WITH_DUMMY_IP	= 0x00,*/
	PET_SYNDROME_DECRYPTED			= 0x11,
	PET_SYNDROME_AUTH_FAILED		= 0x12,
};

struct rcv_pet_content {
	unsigned char   reserved;
	__be32		sa_id;
} __packed;

enum send_pet_syndrome {
	PET_SYNDROME_OFFLOAD = 0x8,
	PET_SYNDROME_OFFLOAD_WITH_LSO_TCP = 0x9,
	PET_SYNDROME_OFFLOAD_WITH_LSO_IPV4 = 0xA,
	PET_SYNDROME_OFFLOAD_WITH_LSO_IPV6 = 0xB,
};

struct send_pet_content {
	__be16 mss_inv;		/* 1/MSS in 16bit fixed point, only for LSO */
	__be16 seq;		/* LSBs of the first TCP seq, only for LSO */
	u8     esp_next_proto;  /* Next protocol of ESP */
} __packed;

struct pet {
	unsigned char syndrome;
	union {
		unsigned char raw[5];
		/* from FPGA to host, on successful decrypt */
		struct rcv_pet_content rcv;
		/* from host to FPGA */
		struct send_pet_content send;
	} __packed content;
	/* packet type ID field	*/
	__be16 ethertype;
} __packed;

enum sadb_encryption_mode {
	SADB_MODE_NONE			= 0,
	SADB_MODE_AES_GCM_128_AUTH_128	= 1,
	SADB_MODE_AES_GCM_256_AUTH_128	= 3,
};

#define SADB_IP_AH       BIT(7)
#define SADB_IP_ESP      BIT(6)
#define SADB_SA_VALID    BIT(5)
#define SADB_SPI_EN      BIT(4)
#define SADB_DIR_SX      BIT(3)
#define SADB_IPV6        BIT(2)

struct __attribute__((__packed__)) sadb_entry {
	u8 key_enc[32];
	u8 key_auth[32];
	__be32 sip[4];
	__be32 dip[4];
	union {
		struct {
			__be32 reserved;
			u8 salt_iv[8];
			__be32 salt;
		} gcm;
		struct {
			u8 salt[16];
		} cbc;
	};
	__be32 spi;
	__be32 sw_sa_handle;
	__be16 tfclen;
	u8 enc_mode;
	u8 sip_masklen;
	u8 dip_masklen;
	u8 flags;
	u8 reserved[2];
};

enum ipsec_response_syndrome {
	IPSEC_RESPONSE_SUCCESS = 0,
	IPSEC_RESPONSE_ILLEGAL_REQUEST = 1,
	IPSEC_RESPONSE_SADB_ISSUE = 2,
	IPSEC_RESPONSE_WRITE_RESPONSE_ISSUE = 3,
	IPSEC_SA_PENDING = 0xff,
};

enum ipsec_hw_cmd {
	IPSEC_CMD_ADD_SA = 0,
	IPSEC_CMD_DEL_SA = 1,
};

struct sa_cmd_v4 {
	__be32 cmd;
	struct sadb_entry entry;
};

struct ipsec_hw_response {
	__be32 syndrome;
	__be32 sw_sa_handle;
	u8 rsvd[24];
};

#endif /* MLX_IPSEC_CMDS_H */
