/* Copyright (c) 2016-2017, Mellanox Technologies All rights reserved.
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
 *      - Neither the name of the Mellanox Technologies nor the
 *        names of its contributors may be used to endorse or promote
 *        products derived from this software without specific prior written
 *        permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE
 */

#ifndef _UAPI_LINUX_TLS_H
#define _UAPI_LINUX_TLS_H

#include <linux/types.h>
#include <asm/byteorder.h>
#include <linux/socket.h>
#include <linux/tcp.h>

/* Supported versions */
#define TLS_VERSION_MINOR(ver)	((ver) & 0xFF)
#define TLS_VERSION_MAJOR(ver)	(((ver) >> 8) & 0xFF)

#define TLS_VERSION_NUMBER(id)	((((id##_VERSION_MAJOR) & 0xFF) << 8) |	\
				 ((id##_VERSION_MINOR) & 0xFF))

#define TLS_1_2_VERSION_MAJOR	0x3
#define TLS_1_2_VERSION_MINOR	0x3
#define TLS_1_2_VERSION		TLS_VERSION_NUMBER(TLS_1_2)

/* Supported ciphers */
#define TLS_CIPHER_AES_GCM_128			51
#define TLS_CIPHER_AES_GCM_128_IV_SIZE		((size_t)8)
#define TLS_CIPHER_AES_GCM_128_KEY_SIZE		((size_t)16)
#define TLS_CIPHER_AES_GCM_128_SALT_SIZE	((size_t)4)
#define TLS_CIPHER_AES_GCM_128_TAG_SIZE		((size_t)16)

enum tls_offload_state {
	TLS_OFFLOAD_STATE_SW = 0x0,
	TLS_OFFLOAD_STATE_HW = 0x1,
};

struct tls_crypto_info {
	__u16 version;
	__u16 cipher_type;
	__u32 offload_state;
};

struct tls_crypto_info_aes_gcm_128 {
	struct tls_crypto_info info;
	unsigned char iv[TLS_CIPHER_AES_GCM_128_IV_SIZE];
	unsigned char key[TLS_CIPHER_AES_GCM_128_KEY_SIZE];
	unsigned char salt[TLS_CIPHER_AES_GCM_128_SALT_SIZE];
};

#endif /* _UAPI_LINUX_TLS_H */
