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

#ifndef __MLX5_FPGA_TLS_H__
#define __MLX5_FPGA_TLS_H__

#ifdef CONFIG_MLX5_EN_TLS

#include <net/tls.h>
#include "en_accel/tls.h"
#include "fpga/tls_cmds.h"

bool mlx5_fpga_is_tls_device(struct mlx5_core_dev *mdev);
int mlx5_fpga_tls_init(struct mlx5_core_dev *mdev);
void mlx5_fpga_tls_cleanup(struct mlx5_core_dev *mdev);

int
mlx5_fpga_tls_hw_start_tx_cmd(struct mlx5_core_dev *mdev, struct sock *sk,
			      struct tls12_crypto_info_aes_gcm_128 *crypto_info,
			      u32 expected_seq, u32 swid);

void mlx5_fpga_tls_hw_stop_tx_cmd(struct mlx5e_priv *priv,
				  struct mlx_tls_offload_context *ctx);

int mlx5_fpga_build_tls_ctx(struct tls12_crypto_info_aes_gcm_128 *crypto_info,
			    enum tls_offload_ctx_dir direction,
			    u32 expected_seq, char *rcd_sn,
			    unsigned short skc_family, struct inet_sock *inet,
			    struct tls_cntx *tls);

#else
static inline int mlx5_fpga_tls_init(struct mlx5_core_dev *mdev)
{
	return 0;
}

static inline void mlx5_fpga_tls_cleanup(struct mlx5_core_dev *mdev) { }

#endif

#endif /* __MLX5_FPGA_TLS_H__ */
