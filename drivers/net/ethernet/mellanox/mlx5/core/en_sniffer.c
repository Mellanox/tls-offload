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

#include "en.h"
#include <linux/mlx5/fs.h>
#include "linux/mlx5/vport.h"

static int mlx5e_create_sniffer_tirs(struct mlx5e_priv *priv)
{
	void *tirc;
	int inlen;
	int err;
	u32 *in;
	int ix;

	inlen = MLX5_ST_SZ_BYTES(create_tir_in);
	in = kvzalloc(inlen, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	for (ix = 0; ix < MLX5E_SNIFFER_NUM_TYPE; ix++) {
		memset(in, 0, inlen);
		tirc = MLX5_ADDR_OF(create_tir_in, in, ctx);
		MLX5_SET(tirc,
			 tirc,
			 transport_domain,
			 priv->mdev->mlx5e_res.td.tdn);
		//MLX5_SET(tirc, tirc, disp_type, MLX5_TIRC_DISP_TYPE_DIRECT);
		//MLX5_SET(tirc, tirc, inline_rqn, priv->channel[0]->rq.rqn);
		MLX5_SET(tirc, tirc, disp_type, MLX5_TIRC_DISP_TYPE_INDIRECT);
		MLX5_SET(tirc, tirc, indirect_table,
			 priv->direct_tir[ix].rqt.rqtn);
		MLX5_SET(tirc, tirc, rx_hash_fn, MLX5_RX_HASH_FN_INVERTED_XOR8);
		MLX5_SET(tirc, tirc, self_lb_block, 0x3);

		err = mlx5_core_create_tir(priv->mdev, in, inlen,
					   &priv->sniffer_tirn[ix]);
		if (err)
			goto err_destroy_sniffer_tirs;
	}

	kvfree(in);
	return 0;

err_destroy_sniffer_tirs:
	for (ix--; ix >= 0; ix--)
		mlx5_core_destroy_tir(priv->mdev, priv->sniffer_tirn[ix]);

	kvfree(in);
	return err;
}

static void mlx5e_destroy_sniffer_tirs(struct mlx5e_priv *priv)
{
	int ix;

	for (ix = 0; ix < MLX5E_SNIFFER_NUM_TYPE; ix++)
		mlx5_core_destroy_tir(priv->mdev, priv->sniffer_tirn[ix]);
}

static int mlx5e_create_sniffer_tables(struct mlx5e_priv *priv)
{
	struct mlx5_core_dev *mdev = priv->mdev;
	struct mlx5_flow_namespace *p_sniffer_tx_ns;
	int err = 0;

	p_sniffer_tx_ns =
		mlx5_get_flow_namespace(mdev, MLX5_FLOW_NAMESPACE_SNIFFER_TX);
	if (!p_sniffer_tx_ns)
		return -ENOENT;

	priv->fs.sniffer.tx_ft = mlx5_create_auto_grouped_flow_table(
					p_sniffer_tx_ns,
					0,
					1,
					1,
					0,
					0);
	if (IS_ERR(priv->fs.sniffer.tx_ft)) {
		priv->fs.sniffer.tx_ft = NULL;
		err = PTR_ERR(priv->fs.sniffer.tx_ft);
	}

	return err;
}

static void mlx5e_destroy_sniffer_tables(struct mlx5e_priv *priv)
{
	if (priv->fs.sniffer.tx_ft)
		mlx5_destroy_flow_table(priv->fs.sniffer.tx_ft);

	priv->fs.sniffer.tx_ft = NULL;
}

static int mlx5e_create_sniffer_tx_rule(struct mlx5e_priv *priv)
{
	struct mlx5_flow_spec spec = {0};
	struct mlx5_flow_act flow_act = {
		.action = MLX5_FLOW_CONTEXT_ACTION_FWD_DEST,
		.flow_tag = MLX5_FS_SNIFFER_FLOW_TAG,
		.encap_id = 0,
	};
	struct mlx5_flow_destination dest;
	int err = 0;

	dest.tir_num = priv->sniffer_tirn[MLX5E_SNIFFER_TX];
	dest.type = MLX5_FLOW_DESTINATION_TYPE_TIR;
	priv->fs.sniffer.tx_fh =
		mlx5_add_flow_rules(
			priv->fs.sniffer.tx_ft,
			&spec,
			&flow_act,
			&dest,
			1);
	if (IS_ERR_OR_NULL(priv->fs.sniffer.tx_fh)) {
		err = PTR_ERR(priv->fs.sniffer.tx_fh);
		priv->fs.sniffer.tx_fh = NULL;
	}

	return err;
}

static void mlx5e_destroy_sniffer_tx_rule(struct mlx5e_priv *priv)
{
	if (priv->fs.sniffer.tx_fh)
		mlx5_del_flow_rules(priv->fs.sniffer.tx_fh);
}

static void mlx5e_sniffer_turn_off(struct net_device *dev)
{
	struct mlx5e_priv *priv = netdev_priv(dev);

	pr_err("mlx5e_sniffer_turn_off\n");

	mlx5e_destroy_sniffer_tx_rule(priv);
	mlx5e_destroy_sniffer_tables(priv);
	mlx5e_destroy_sniffer_tirs(priv);
}

static int mlx5e_sniffer_turn_on(struct net_device *dev)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	int err;

	pr_err("mlx5e_sniffer_turn_on\n");

	/* TIRs already created during RQ creation */
	err = mlx5e_create_sniffer_tirs(priv);
	if (err)
		goto err;

	err = mlx5e_create_sniffer_tables(priv);
	if (err)
		goto err_create_sniffer_tirs;

	err = mlx5e_create_sniffer_tx_rule(priv);
	if (err)
		goto err_create_sniffer_tables;

	return 0;
err_create_sniffer_tirs:
	mlx5e_destroy_sniffer_tirs(priv);
err_create_sniffer_tables:
	mlx5e_destroy_sniffer_tables(priv);
err:
	return err;
}

int set_pflag_sniffer(struct net_device *netdev, bool enable)
{
	int err = 0;

	pr_err("set_pflag_sniffer=%d\n", enable);
	if (enable)
		err = mlx5e_sniffer_turn_on(netdev);
	else
		mlx5e_sniffer_turn_off(netdev);

	return err;
}

