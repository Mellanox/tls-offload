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

#include "../core/accel_core_sdk.h"
#include "ipsec.h"
#include "ipsec_sysfs.h"
#include "ipsec_hw.h"
#include <linux/netdevice.h>

static LIST_HEAD(mlx_ipsec_devs);
static DEFINE_MUTEX(mlx_ipsec_mutex);
static int mlx_xfrm_add_state(struct xfrm_state *x);
static void mlx_xfrm_del_state(struct xfrm_state *x);
static void mlx_xfrm_free_state(struct xfrm_state *x);
static int mlx_ipsec_dev_crypto(struct sk_buff *skb);
static struct sk_buff *mlx_ipsec_rx_handler(struct sk_buff *skb);
static struct sk_buff *mlx_ipsec_tx_handler(struct sk_buff *skb);
static u16             mlx_ipsec_mtu_handler(u16 mtu, bool is_sw2hw);

static const struct xfrmdev_ops mlx_xfrmdev_ops = {
	.xdo_dev_state_add	= mlx_xfrm_add_state,
	.xdo_dev_state_delete	= mlx_xfrm_del_state,
	.xdo_dev_state_free = mlx_xfrm_free_state,
	.xdo_dev_crypto		= mlx_ipsec_dev_crypto,
};

static struct mlx5e_accel_client_ops mlx_ipsec_client_ops = {
	.rx_handler   = mlx_ipsec_rx_handler,
	.tx_handler   = mlx_ipsec_tx_handler,
	.mtu_handler  = mlx_ipsec_mtu_handler,
};

/* must hold mlx_ipsec_mutex to call this function */
static struct mlx_ipsec_dev *find_mlx_ipsec_dev_by_netdev(
		struct net_device *netdev)
{
	struct mlx_ipsec_dev *dev;

	list_for_each_entry(dev, &mlx_ipsec_devs, accel_dev_list) {
		if (dev->netdev == netdev)
			return dev;
	}

	return NULL;
}

struct mlx_ipsec_dev *mlx_ipsec_find_dev_by_netdev(struct net_device *netdev)
{
	struct mlx_ipsec_dev *dev;

	mutex_lock(&mlx_ipsec_mutex);
	dev = find_mlx_ipsec_dev_by_netdev(netdev);
	mutex_unlock(&mlx_ipsec_mutex);
	return dev;
}

static void mlx_ipsec_set_clear_bypass(struct mlx_ipsec_dev *dev, bool set)
{
	int res;
	u32 dw;

	res = mlx_accel_core_mem_read(dev->accel_device, 4,
				      IPSEC_BYPASS_ADDR, &dw,
				      MLX_ACCEL_ACCESS_TYPE_DONTCARE);
	if (res != 4) {
		pr_warn("IPSec bypass clear failed on read\n");
		return;
	}

	dw = set ? dw | IPSEC_BYPASS_BIT : dw & ~IPSEC_BYPASS_BIT;
	res = mlx_accel_core_mem_write(dev->accel_device, 4,
				       IPSEC_BYPASS_ADDR, &dw,
				       MLX_ACCEL_ACCESS_TYPE_DONTCARE);
	if (res != 4) {
		pr_warn("IPSec bypass clear failed on write\n");
		return;
	}
}

/*
 * returns 0 on success, negative error if failed to send message to FPGA
 * positive error if FPGA returned a bad response
 */
static int mlx_xfrm_add_state(struct xfrm_state *x)
{
	struct net_device *netdev = x->xso.dev;
	struct mlx_ipsec_dev *dev;
	struct mlx_ipsec_sa_entry *sa_entry = NULL;
	unsigned long flags;
	int res;

	if (x->props.mode != XFRM_MODE_TUNNEL) {
		dev_info(&netdev->dev, "Only tunnel xfrm state may be offloaded\n");
		return -EINVAL;
	}
	if (x->props.aalgo != SADB_AALG_NONE) {
		dev_info(&netdev->dev, "Cannot offload authenticated xfrm states\n");
		return -EINVAL;
	}
	if (x->props.ealgo != SADB_X_EALG_AES_GCM_ICV16) {
		dev_info(&netdev->dev, "Only AES-GCM-ICV16 xfrm state may be offloaded\n");
		return -EINVAL;
	}
	if (x->props.calgo != SADB_X_CALG_NONE) {
		dev_info(&netdev->dev, "Cannot offload compressed xfrm states\n");
		return -EINVAL;
	}
	if (x->props.flags != 0) {
		dev_info(&netdev->dev, "Cannot offload xfrm states with flags\n");
		return -EINVAL;
	}
	if (x->props.family != AF_INET) {
		dev_info(&netdev->dev, "Only IPv4 xfrm state may be offloaded\n");
		return -EINVAL;
	}
	if (x->props.extra_flags != 0) {
		dev_info(&netdev->dev, "Cannot offload xfrm states with extra flags\n");
		return -EINVAL;
	}
	if (!x->aead) {
		dev_info(&netdev->dev, "Cannot offload xfrm states without aead\n");
		return -EINVAL;
	}
	if (x->aead->alg_icv_len != 128) {
		dev_info(&netdev->dev, "Cannot offload xfrm states with AEAD ICV length other than 128bit\n");
		return -EINVAL;
	}
	if ((x->aead->alg_key_len != 128 + 32) &&
	    (x->aead->alg_key_len != 256 + 32)) {
		dev_info(&netdev->dev, "Cannot offload xfrm states with AEAD key length other than 128/256 bit\n");
		return -EINVAL;
	}
	pr_debug("add_sa(): key_len %d\n",
			(x->aead->alg_key_len + 7) / 8 - 4);

	dev = mlx_ipsec_find_dev_by_netdev(netdev);
	if (!dev) {
		res = -EINVAL;
		goto out;
	}

	sa_entry = kzalloc(sizeof(struct mlx_ipsec_sa_entry), GFP_ATOMIC);
	if (!sa_entry) {
		res = -ENOMEM;
		goto out;
	}

	sa_entry->hw_sa_id = UNASSIGNED_SA_ID;
	sa_entry->sw_sa_id = atomic_inc_return(&dev->next_sw_sa_id);
	/* WA HW bug - sw sa ID isn't respected, and instead set to sa_index */
	sa_entry->sw_sa_id = (ntohl(x->id.daddr.a4) ^ ntohl(x->id.spi)) &
			     0xFFFFF;
	sa_entry->x = x;
	sa_entry->dev = dev;

	/* Add the SA to handle processed incoming packets before the add SA
	 * completion was received
	 */
	if (x->xso.flags & XFRM_OFFLOAD_INBOUND) {
		spin_lock_irqsave(&dev->sw_sa_id2xfrm_state_lock, flags);
		hash_add_rcu(dev->sw_sa_id2xfrm_state_table, &sa_entry->hlist,
				sa_entry->sw_sa_id);
		spin_unlock_irqrestore(&dev->sw_sa_id2xfrm_state_lock, flags);
	}

	sa_entry->status = ADD_SA_PENDING;
	res = mlx_ipsec_hw_sadb_add(sa_entry, dev);
	if (res)
		goto err_hash_rcu;

	x->xso.offload_handle = (unsigned long)sa_entry;
	try_module_get(THIS_MODULE);
	goto out;

err_hash_rcu:
	if (x->xso.flags & XFRM_OFFLOAD_INBOUND) {
		spin_lock_irqsave(
				&dev->sw_sa_id2xfrm_state_lock,
				flags);
		hash_del_rcu(&sa_entry->hlist);
		spin_unlock_irqrestore(
				&dev->sw_sa_id2xfrm_state_lock,
				flags);
		synchronize_rcu();
	}

	kfree(sa_entry);
	sa_entry = NULL;
out:
	return res;
}

static void mlx_xfrm_del_state(struct xfrm_state *x)
{
	struct mlx_ipsec_sa_entry *sa_entry;
	int res;

	if (x->xso.offload_handle) {
		sa_entry = (struct mlx_ipsec_sa_entry *)x->xso.offload_handle;

		WARN_ON(sa_entry->x != x);
		res = mlx_ipsec_hw_sadb_del(sa_entry);
		if (res)
			pr_warn("Delete SADB entry from HW failed %d\n", res);

		/* Todo: Need to delete from rcu hashtable, kfree and
		 * module_put. But synch_rcu might sleep, and this is atomic
		 * context
		 */
	}
}

static void mlx_xfrm_free_state(struct xfrm_state *x)
{
	/* [AY/IT] TODO: workaround until take patches. */
}

static struct xfrm_state *mlx_sw_sa_id_to_xfrm_state(struct mlx_ipsec_dev *dev,
		unsigned int sw_sa_id) {
	struct mlx_ipsec_sa_entry *sa_entry;

	rcu_read_lock();
	hash_for_each_possible_rcu(dev->sw_sa_id2xfrm_state_table, sa_entry,
				hlist, sw_sa_id) {
		if (sa_entry->sw_sa_id == sw_sa_id) {
			rcu_read_unlock();
			return sa_entry->x;
		}
	}
	rcu_read_unlock();
	pr_warn("mlx_sw_sa_id_to_xfrm_state(): didn't find SA entry for %x\n",
		sw_sa_id);
	return NULL;
}

static void remove_pet(struct sk_buff *skb, struct pet *pet)
{
	struct ethhdr *old_eth;
	struct ethhdr *new_eth;

	pr_debug("remove_pet started\n");

	memcpy(pet, skb->data, sizeof(*pet));
	old_eth = (struct ethhdr *)(skb->data - sizeof(struct ethhdr));
	new_eth = (struct ethhdr *)(skb_pull_inline(skb, sizeof(struct pet)) -
		sizeof(struct ethhdr));
	skb->mac_header += sizeof(struct pet);

	memmove(new_eth, old_eth, 2 * ETH_ALEN);
	/* Ethertype is already in its new place */
}

static void remove_dummy_dword(struct sk_buff *skb)
{
	struct iphdr *iphdr = (struct iphdr *)skb->data;
	unsigned char *old;
	unsigned char *new;
	unsigned int iphdr_len = iphdr->ihl * 4;

	pr_debug("remove_dummy_dword started\n");

	/* We expect IP header right after the PET
	 * with no IP options, all other are not offloaded for now
	 */
	if (be16_to_cpu(skb->protocol) != ETH_P_IP)
		pr_warn("expected ETH_P_IP but received %04x\n",
			be16_to_cpu(skb->protocol));
	if (iphdr_len > sizeof(struct iphdr))
		pr_warn("expected ETH_P_IP without IP options\n");

#ifdef DEBUG
	print_hex_dump_bytes("pkt with dummy dword ", DUMP_PREFIX_OFFSET,
			     skb->data, skb->len);
#endif

	if (iphdr->protocol != IPPROTO_DUMMY_DWORD)
		return;

	old = skb->data - sizeof(struct ethhdr);
	new = skb_pull_inline(skb, sizeof(struct dummy_dword)) -
			      sizeof(struct ethhdr);
	iphdr->protocol = IPPROTO_ESP; /* TODO */
	iphdr->tot_len = htons(ntohs(iphdr->tot_len) - 4);
	iphdr->check = htons(~(~ntohs(iphdr->check) - 0xd1));

	memmove(new, old, ETH_HLEN + iphdr_len);

	skb->mac_header += sizeof(struct dummy_dword);
}

static int insert_pet(struct sk_buff *skb)
{
	struct ethhdr *eth;
	struct pet *pet;

	pr_debug("insert_pet started\n");
	if (skb_cow_head(skb, sizeof(struct pet)))
		return -ENOMEM;

	eth = (struct ethhdr *)skb_push(skb, sizeof(struct pet));
	skb->mac_header -= sizeof(struct pet);
	pet = (struct pet *)(eth+1);

	memmove(skb->data, skb->data + sizeof(struct pet), 2 * ETH_ALEN);

	eth->h_proto = cpu_to_be16(MLX_IPSEC_PET_ETHERTYPE);

	pet->syndrome = PET_SYNDROME_OFFLOAD_REQUIRED;
	memset(pet->content.raw, 0, sizeof(pet->content.raw));

	return 0;
}

static int mlx_ipsec_dev_crypto(struct sk_buff *skb)
{
	struct dst_entry *dst = skb_dst(skb);

	if (skb_is_gso(skb)) {
		if (skb_gso_network_seglen(skb) >
		    ip_skb_dst_mtu(skb->sk, skb)) {
			/* This GSO packet is about to be IP-fragmented */
			pr_info_ratelimited("Skipping offload of %u-seglen GSO packet on path mtu %u\n",
					    skb_gso_network_seglen(skb),
					    ip_skb_dst_mtu(skb->sk, skb));
			return 0;
		}
	} else {
		if (skb->len > dst_mtu(dst->path)) {
			/* This packet is about to be IP-fragmented */
			pr_info_ratelimited("Skipping offload of %u-bytes packet on path mtu %u\n",
					    skb->len, dst_mtu(dst->path));
			return 0;
		}
		skb->sp->flags |= SKB_CRYPTO_OFFLOAD;
	}

	return 1;
}

static u16 mlx_ipsec_mtu_handler(u16 mtu, bool is_sw2hw)
{
	u16 mtu_diff = sizeof(struct pet) + sizeof(struct dummy_dword);

	if (is_sw2hw)
		return mtu + mtu_diff;
	else
		return mtu - mtu_diff;
}

static struct sk_buff *mlx_ipsec_tx_handler(struct sk_buff *skb)
{
	struct xfrm_state *x;
	pr_debug("mlx_ipsec_tx_handler started\n");

	if (!skb->sp)
		goto out;

	if (!(skb->sp->flags & SKB_CRYPTO_OFFLOAD))
		goto out;

	if (skb->sp->len != 1) {
		pr_warn_ratelimited("Cannot offload crypto for a bundle of %u XFRM states\n",
				    skb->sp->len);
		goto out;
	}

	x = skb->sp->xvec[0];
	if (!x) {
		pr_warn_ratelimited("Crypto-offload packet has no xfrm_state\n");
		goto out;
	}

	if (x->xso.offload_handle &&
	    skb->protocol == htons(ETH_P_IP)) {
		if (insert_pet(skb)) {
			pr_warn("insert_pet failed!!\n");
			kfree_skb(skb);
			skb = NULL;
		}
	}
out:
	return skb;
}

static struct sk_buff *mlx_ipsec_rx_handler(struct sk_buff *skb)
{
	struct pet pet;
	struct xfrm_offload_state *xos;
	struct mlx_ipsec_dev *dev;
	struct xfrm_state *xs;

	/* [BP]: TODO - process incoming PET here */
	if (skb->protocol != cpu_to_be16(MLX_IPSEC_PET_ETHERTYPE)) {
		pr_debug("mlx_ipsec_rx_handler: got normal packet\n");
		goto out;
	}
	pr_debug("mlx_ipsec_rx_handler: processing PET\n");

	remove_pet(skb, &pet);
	pr_debug("size %lu, etherType %04X, syndrome %02x, sw_sa_id %x\n",
		 sizeof(pet), be16_to_cpu(pet.ethertype), pet.syndrome,
		 be32_to_cpu(pet.content.rcv.sa_id));

	skb->protocol = pet.ethertype;

	remove_dummy_dword(skb);

	WARN_ON(skb->sp != NULL);
	skb->sp = secpath_dup(skb->sp);
	if (unlikely(!skb->sp)) { /* drop */
		pr_warn("Failed to allocate secpath - dropping!\n");
		goto drop;
	}

	/* [BP]: TODO - this should use a mutex.
	 * But, we can't do this under interrupt context.
	 */
	dev = find_mlx_ipsec_dev_by_netdev(skb->dev);
	xs = mlx_sw_sa_id_to_xfrm_state(dev,
			be32_to_cpu(pet.content.rcv.sa_id));

	if (!xs) {
		pr_warn("No xfrm_state found for processed packet\n");
		goto drop;
	}

	/* xfrm_input expects us to hold the xfrm_state */
	xfrm_state_hold(xs);
	skb->sp->xvec[skb->sp->len++] = xs;

	xos = xfrm_offload_input(skb);
	xos->flags = CRYPTO_DONE;
	switch (pet.syndrome) {
	case PET_SYNDROME_DECRYPTED:
		xos->status = CRYPTO_SUCCESS;
		break;
	case PET_SYNDROME_AUTH_FAILED:
		xos->status = CRYPTO_TUNNEL_ESP_AUTH_FAILED;
		break;
	default:
		pr_warn("Unknown metadata syndrom\n");
		goto drop;
	}
	goto out;

drop:
	kfree_skb(skb);
	pr_debug("mlx_ipsec_rx_handler: dropping packet\n");
	skb = NULL;
out:
	return skb;
}

/* Must hold mlx_ipsec_mutex to call this function.
 * Assumes that dev->core_ctx is destroyed be the caller
 */
static void mlx_ipsec_free(struct mlx_ipsec_dev *dev)
{
	list_del(&dev->accel_dev_list);
	kobject_put(&dev->kobj);
}

void mlx_ipsec_dev_release(struct kobject *kobj)
{
	struct mlx_ipsec_dev *ipsec_dev =
			container_of(kobj, struct mlx_ipsec_dev, kobj);

	/*
	 * [BP]: TODO - Test the corner case of removing the last reference
	 * while receiving packets that should be handled by the rx_handler.
	 * Do we need some sync here?
	 */

	dev_put(ipsec_dev->netdev);

	kfree(ipsec_dev);
}

int mlx_ipsec_netdev_event(struct notifier_block *this,
		unsigned long event, void *ptr)
{
	struct net_device *netdev = netdev_notifier_info_to_dev(ptr);
	struct mlx_ipsec_dev *accel_dev = NULL;

	if (!netdev)
		goto out;

	pr_debug("mlx_ipsec_netdev_event: %lu\n", event);

	/* We are interested only in net devices going down */
	if (event != NETDEV_UNREGISTER)
		goto out;

	/* Take down all connections using a netdev that is going down */
	mutex_lock(&mlx_ipsec_mutex);
	accel_dev = find_mlx_ipsec_dev_by_netdev(netdev);
	if (!accel_dev) {
		pr_debug("mlx_ipsec_netdev_event: Failed to find ipsec device for net device\n");
		goto unlock;
	}
	mlx_accel_core_client_ops_unregister(netdev);
	mlx_ipsec_free(accel_dev);

unlock:
	mutex_unlock(&mlx_ipsec_mutex);
out:
	return NOTIFY_DONE;
}

int mlx_ipsec_add_one(struct mlx_accel_core_device *accel_device)
{
	int ret = 0;
	struct mlx_ipsec_dev *dev = NULL;
	struct net_device *netdev = NULL;
	struct mlx_accel_core_conn_init_attr init_attr = {0};

	pr_debug("mlx_ipsec_add_one called for %s\n", accel_device->name);

	dev = kzalloc(sizeof(struct mlx_ipsec_dev), GFP_KERNEL);
	if (!dev) {
		ret = -ENOMEM;
		goto out;
	}

	init_waitqueue_head(&dev->wq);
	INIT_LIST_HEAD(&dev->accel_dev_list);
	INIT_KFIFO(dev->fifo_sa_cmds);
	hash_init(dev->sw_sa_id2xfrm_state_table);
	spin_lock_init(&dev->sw_sa_id2xfrm_state_lock);
	spin_lock_init(&dev->fifo_sa_cmds_lock);
	atomic_set(&dev->next_sw_sa_id, 0);
	dev->accel_device = accel_device;

	/* [BP]: TODO: Move these constants to a header */
	init_attr.rx_size = 128;
	init_attr.tx_size = 32;
	init_attr.recv_cb = mlx_ipsec_hw_qp_recv_cb;
	init_attr.cb_arg = dev;
	/* [AY]: TODO: fix port 1 issue */
	dev->conn = mlx_accel_core_conn_create(accel_device, &init_attr);
	if (IS_ERR(dev->conn)) {
		ret = PTR_ERR(dev->conn);
		pr_err("mlx_ipsec_add_one(): Got error while creating connection %d\n",
				ret);
		goto err_dev;
	}

	netdev = accel_device->ib_dev->get_netdev(accel_device->ib_dev,
			dev->conn->port_num);
	if (!netdev) {
		pr_err("mlx_ipsec_add_one(): Failed to retrieve net device from ib device\n");
		ret = -EINVAL;
		goto err_conn;
	}
	dev->netdev = netdev;

	netif_keep_dst(dev->netdev);

	ret = mlx_accel_core_client_ops_register(netdev, &mlx_ipsec_client_ops);
	if (ret) {
		pr_err("mlx_ipsec_add_one(): Failed to register client ops %d\n",
		       ret);
		goto err_netdev;
	}

	ret = ipsec_sysfs_init_and_add(&dev->kobj,
			mlx_accel_core_kobj(dev->accel_device),
			"%s",
			"accel_dev");
	if (ret) {
		pr_err("mlx_ipsec_add_one(): Got error from kobject_init_and_add %d\n", ret);
		goto err_ops_register;
	}

	mutex_lock(&mlx_ipsec_mutex);
	list_add(&dev->accel_dev_list, &mlx_ipsec_devs);
	mutex_unlock(&mlx_ipsec_mutex);

	/* Add NETIF_F_HW_ESP feature */
	dev->netdev->xfrmdev_ops = &mlx_xfrmdev_ops;
	dev->netdev->wanted_features |= NETIF_F_HW_ESP;
	rtnl_lock();
	netdev_change_features(dev->netdev);
	rtnl_unlock();

	mlx_ipsec_set_clear_bypass(dev, false);
	goto out;

err_ops_register:
	mlx_accel_core_client_ops_unregister(netdev);
err_netdev:
	dev_put(netdev);
err_conn:
	mlx_accel_core_conn_destroy(dev->conn);
err_dev:
	kfree(dev);
out:
	return ret;
}

/* [BP]: TODO - Remove all SA entries on mlx_xfrm_del_state */
/* [BP]: TODO - How do we make sure that all packets inflight are dropped? */
void mlx_ipsec_remove_one(struct mlx_accel_core_device *accel_device)
{
	struct mlx_ipsec_dev *dev;
	struct net_device *netdev = NULL;

	pr_debug("mlx_ipsec_remove_one called for %s\n", accel_device->name);

	mutex_lock(&mlx_ipsec_mutex);

	list_for_each_entry(dev, &mlx_ipsec_devs, accel_dev_list) {
		if (dev->accel_device == accel_device) {
			dev->netdev->wanted_features &= ~NETIF_F_HW_ESP;
			netdev = dev->netdev;
			mlx_accel_core_conn_destroy(dev->conn);
			mlx_ipsec_set_clear_bypass(dev, true);
			mlx_accel_core_client_ops_unregister(netdev);
			mlx_ipsec_free(dev);
			break;
		}
	}
	mutex_unlock(&mlx_ipsec_mutex);

	/* Remove NETIF_F_HW_ESP feature.
	 * We assume that xfrm ops are assigned by xfrm_dev notifier callback
	 */
	if (netdev) {
		rtnl_lock();
		netdev_change_features(netdev);
		rtnl_unlock();
	}
}
