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
#include "tls.h"
#include "tls_sysfs.h"
#include "tls_hw.h"
#include "tls_cmds.h"
#include <linux/mlx5/driver.h>
#include <linux/netdevice.h>

static LIST_HEAD(mlx_tls_devs);
static DEFINE_MUTEX(mlx_tls_mutex);

/* Start of context identifiers range (inclusive) */
#define SWID_START	5
/* End of context identifiers range (exclusive) */
#define SWID_END	BIT(24)

static netdev_features_t mlx_tls_feature_chk(struct sk_buff *skb,
					     struct net_device *netdev,
					     netdev_features_t features,
					     bool *done)
{
	return features;
}

int mlx_tls_get_count(struct net_device *netdev)
{
	return 0;
}

int mlx_tls_get_strings(struct net_device *netdev, uint8_t *data)
{
	return 0;
}

int mlx_tls_get_stats(struct net_device *netdev, u64 *data)
{
	return 0;
}

/* must hold mlx_tls_mutex to call this function */
static struct mlx_tls_dev *find_mlx_tls_dev_by_netdev(
		struct net_device *netdev)
{
	struct mlx_tls_dev *dev;

	list_for_each_entry(dev, &mlx_tls_devs, accel_dev_list) {
		if (dev->netdev == netdev)
			return dev;
	}

	return NULL;
}

struct mlx_tls_offload_context *get_tls_context(struct sock *sk)
{
	struct tls_context *ctx = sk->sk_user_data;

	return container_of(ctx->offload_ctx,
			    struct mlx_tls_offload_context,
			    context);
}

static int mlx_tls_add(struct net_device *netdev,
		       struct sock *sk,
		       bool is_send,
		       struct tls_crypto_info *crypto_info,
		       struct tls_offload_context **ctx)
{
	struct tls_crypto_info_aes_gcm_128 *crypto_info_aes_gcm_128;
	struct mlx_tls_offload_context *context;
	struct mlx_tls_dev *dev;
	int swid;
	int ret;

	pr_info("mlx_tls_add called\n");

	if (!is_send) {
		pr_err("mlx_tls_add(): do not support recv\n");
		ret = -EINVAL;
		goto out;
	}

	if (!crypto_info ||
	    crypto_info->cipher_type != TLS_CIPHER_AES_GCM_128) {
		pr_err("mlx_tls_add(): support only aes_gcm_128\n");
		ret = -EINVAL;
		goto out;
	}
	crypto_info_aes_gcm_128 =
			(struct tls_crypto_info_aes_gcm_128 *)crypto_info;

	dev = mlx_tls_find_dev_by_netdev(netdev);
	if (!dev) {
		pr_err("mlx_tls_add(): tls dev not found\n");
		ret = -EINVAL;
		goto out;
	}

	swid = ida_simple_get(&dev->swid_ida, SWID_START, SWID_END,
			      GFP_KERNEL);
	if (swid < 0) {
		pr_err("mlx_tls_add(): Failed to allocate swid\n");
		ret = swid;
		goto out;
	}

	context = kzalloc(sizeof(*context), GFP_KERNEL);
	if (!context) {
		ret = -ENOMEM;
		goto release_swid;
	}

	context->swid = htonl(swid);
	context->context.expectedSN = tcp_sk(sk)->write_seq;

	ret = mlx_tls_hw_start_cmd(dev,
				   sk,
				   is_send,
				   crypto_info_aes_gcm_128,
				   context);
	if (ret)
		goto relese_context;

	try_module_get(THIS_MODULE);
	*ctx = &context->context;
out:
	return ret;

relese_context:
	kfree(context);
release_swid:
	ida_simple_remove(&dev->swid_ida, swid);
	return ret;
}

static void mlx_tls_del(struct net_device *netdev,
			struct sock *sk,
			bool is_send)
{
	struct mlx_tls_offload_context *context = NULL;

	if (!is_send) {
		pr_err("mlx_tls_del(): do not support recv\n");
		return;
	}

	context = get_tls_context(sk);
	if (context)
		mlx_tls_hw_stop_cmd(netdev, context);
	else
		pr_err("delete non-offloaded context\n");
}

static const struct tlsdev_ops mlx_tls_ops = {
	.tls_dev_add = mlx_tls_add,
	.tls_dev_del = mlx_tls_del,
};

struct mlx_tls_dev *mlx_tls_find_dev_by_netdev(struct net_device *netdev)
{
	struct mlx_tls_dev *dev;

	mutex_lock(&mlx_tls_mutex);
	dev = find_mlx_tls_dev_by_netdev(netdev);
	mutex_unlock(&mlx_tls_mutex);
	return dev;
}

#define SYNDROME_OFFLOAD_REQUIRED 32
#define SYNDROME_SYNC 33.
#define SYNDROME_BYPASS 34

#define MIN_BYPASS_RECORD_SIZE 29
#define BYPASS_RECORD_PADDING_SIZE \
		(MIN_BYPASS_RECORD_SIZE - TLS_HEADER_SIZE)

#define MAX_BYPASS_SIZE ((1 << 15) - BYPASS_RECORD_PADDING_SIZE - 1)

static void create_bypass_record(u8 *buf, u16 len)
{
	len += BYPASS_RECORD_PADDING_SIZE;
	buf[0] = TLS_RECORD_TYPE_DATA;
	buf[1] = TLS_1_2_VERSION_MAJOR;
	buf[2] = TLS_1_2_VERSION_MINOR;
	buf[3] = len >> 8;
	buf[4] = len & 0xFF;
	memset(buf + TLS_HEADER_SIZE, 0, BYPASS_RECORD_PADDING_SIZE);
}

struct sync_info {
	s32 sync_len;
	int nr_frags;
	skb_frag_t frags[MAX_SKB_FRAGS];
};

static int get_sync_data(struct mlx_tls_offload_context *context,
			 u32 tcp_seq, struct sync_info *info)
{
	struct tls_record_info *record;
	unsigned long flags;
	int remaining;
	s32 sync_size;
	int ret = -EINVAL;
	int i = 0;

	spin_lock_irqsave(&context->context.lock, flags);
	record = tls_get_record(&context->context, tcp_seq);

	if (unlikely(!record)) {
		pr_err("record not found for seq %u\n", tcp_seq);
		goto out;
	}

	sync_size = tcp_seq - (record->end_seq - record->len);
	info->sync_len = sync_size;
	if (unlikely(sync_size < 0)) {
		if (record->len != 0) {
			pr_err("Invalid record for seq %u\n", tcp_seq);
			goto out;
		}
		goto done;
	}

	remaining = sync_size;
	while (remaining > 0) {
		info->frags[i] = record->frags[i];
		__skb_frag_ref(&info->frags[i]);
		remaining -= skb_frag_size(&info->frags[i]);

		if (remaining < 0) {
			skb_frag_size_add(
					&info->frags[i],
					remaining);
		}

		i++;
	}
	info->nr_frags = i;
done:
	ret = 0;
out:
	spin_unlock_irqrestore(&context->context.lock, flags);
	return ret;
}

static struct sk_buff *complete_sync_skb(
		struct sk_buff *skb,
		struct sk_buff *nskb,
		u32 tcp_seq,
		int headln,
		unsigned char syndrome
		)
{
	struct iphdr *iph;
	struct tcphdr *th;
	int mss;
	struct pet *pet;
	__be16 tcp_seq_low;

	nskb->dev = skb->dev;
	skb_reset_mac_header(nskb);
	skb_set_network_header(nskb, skb_network_offset(skb));
	skb_set_transport_header(nskb, skb_transport_offset(skb));
	memcpy(nskb->data, skb->data, headln);

	iph = ip_hdr(nskb);
	iph->tot_len = htons(nskb->len - skb_network_offset(nskb));
	th = tcp_hdr(nskb);
	tcp_seq -= nskb->data_len;
	th->seq = htonl(tcp_seq);
	tcp_seq_low = htons(tcp_seq);

	mss = nskb->dev->mtu - (headln - skb_network_offset(nskb));
	skb_shinfo(nskb)->gso_size = 0;
	if (nskb->data_len > mss) {
		skb_shinfo(nskb)->gso_size = mss;
		skb_shinfo(nskb)->gso_segs = DIV_ROUND_UP(nskb->data_len, mss);
	}
	skb_shinfo(nskb)->gso_type = skb_shinfo(skb)->gso_type;

	nskb->queue_mapping = skb->queue_mapping;

	pet = (struct pet *)(nskb->data + sizeof(struct ethhdr));
	pet->syndrome = syndrome;
	memcpy(pet->content.raw, &tcp_seq_low, sizeof(tcp_seq_low));

	nskb->ip_summed = CHECKSUM_PARTIAL;
	__skb_pull(nskb, skb_transport_offset(skb));
	inet_csk(skb->sk)->icsk_af_ops->send_check(skb->sk, nskb);
	__skb_push(nskb, skb_transport_offset(skb));

	nskb->next = skb;
	nskb->xmit_more = 1;
	return nskb;
}

static void strip_pet(struct sk_buff *skb)
{
	struct ethhdr *old_eth;
	struct ethhdr *new_eth;

	old_eth = (struct ethhdr *)((skb->data)  - sizeof(struct ethhdr));
	new_eth = (struct ethhdr *)((skb_pull_inline(skb, sizeof(struct pet)))
			- sizeof(struct ethhdr));
	skb->mac_header += sizeof(struct pet);

	memmove(new_eth, old_eth, 2 * ETH_ALEN);
	/* Ethertype is already in its new place */
}

static struct sk_buff *handle_ooo(struct mlx_tls_offload_context *context,
				  struct sk_buff *skb)
{
	struct sync_info info;
	u32 tcp_seq = ntohl(tcp_hdr(skb)->seq);
	struct sk_buff *nskb;
	int linear_len = 0;
	int headln;
	unsigned char syndrome = SYNDROME_SYNC;

	if (get_sync_data(context, tcp_seq, &info)) {
		dev_kfree_skb_any(skb);
		return NULL;
	}

	headln = skb_transport_offset(skb) + tcp_hdrlen(skb);

	if (unlikely(info.sync_len < 0)) {
		if (-info.sync_len > MAX_BYPASS_SIZE) {
			if (skb->len - headln > -info.sync_len) {
				pr_err("Required bypass record is too big\n");
				/* can fragment into two large SKBs in SW */
				return NULL;
			}
			skb_push(skb, sizeof(struct ethhdr));
			strip_pet(skb);
			skb_pull(skb, sizeof(struct ethhdr));
			return skb;
		}

		linear_len = MIN_BYPASS_RECORD_SIZE;
	}

	linear_len += headln;
	nskb = alloc_skb(linear_len, GFP_ATOMIC);
	if (unlikely(!nskb)) {
		dev_kfree_skb_any(skb);
		return NULL;
	}

	skb_put(nskb, linear_len);
	syndrome = SYNDROME_SYNC;
	if (likely(info.sync_len >= 0)) {
		int i;

		for (i = 0; i < info.nr_frags; i++)
			skb_shinfo(nskb)->frags[i] = info.frags[i];

		skb_shinfo(nskb)->nr_frags = info.nr_frags;
		nskb->data_len = info.sync_len;
		nskb->len += info.sync_len;
	} else {
		create_bypass_record(nskb->data + headln, -info.sync_len);
		tcp_seq -= MIN_BYPASS_RECORD_SIZE;
		syndrome = SYNDROME_BYPASS;
	}

	return complete_sync_skb(skb, nskb, tcp_seq, headln, syndrome);
}

static int insert_pet(struct sk_buff *skb)
{
	struct ethhdr *eth;
	struct pet *pet;
	struct mlx_tls_offload_context *context;

	pr_debug("insert_pet started\n");
	if (skb_cow_head(skb, sizeof(struct pet)))
		return -ENOMEM;

	eth = (struct ethhdr *)skb_push(skb, sizeof(struct pet));
	skb->mac_header -= sizeof(struct pet);
	pet = (struct pet *)(eth + 1);

	memmove(skb->data, skb->data + sizeof(struct pet), 2 * ETH_ALEN);

	eth->h_proto = cpu_to_be16(MLX5_METADATA_ETHER_TYPE);
	pet->syndrome = SYNDROME_OFFLOAD_REQUIRED;

	memset(pet->content.raw, 0, sizeof(pet->content.raw));
	context = get_tls_context(skb->sk);
	memcpy(pet->content.send.sid, &context->swid,
	       sizeof(pet->content.send.sid));

	return 0;
}

static struct sk_buff *mlx_tls_tx_handler(struct sk_buff *skb,
					  struct mlx5_swp_info *swp_info)
{
	struct mlx_tls_offload_context *context;
	int datalen;
	u32 skb_seq;

	pr_debug("mlx_tls_tx_handler started\n");

	/* TODO: [Aviadye]: check if TLS TX HW */
	if (!skb->sk || !tls_is_sk_tx_offloaded(skb->sk))
		goto out;

	datalen = skb->len - (skb_transport_offset(skb) + tcp_hdrlen(skb));
	if (!datalen)
		goto out;

	skb_seq =  ntohl(tcp_hdr(skb)->seq);

	context = get_tls_context(skb->sk);
	pr_debug("mlx_tls_tx_handler: mapping: %u cpu %u size %u with swid %u expectedSN: %u actualSN: %u\n",
		 skb->queue_mapping, smp_processor_id(), skb->len,
		 ntohl(context->swid), context->context.expectedSN, skb_seq);

	insert_pet(skb);
	/* TODO: do something useful with swp_info?!? */

	if (unlikely(context->context.expectedSN != skb_seq)) {
		skb = handle_ooo(context, skb);
		if (!skb)
			goto out;

		pr_info("Sending sync packet\n");

		if (!skb->next)
			goto out;
	}
	context->context.expectedSN = skb_seq + datalen;

out:
	return skb;
}

static struct sk_buff *mlx_tls_rx_handler(struct sk_buff *skb, u8 *rawpet,
					  u8 petlen)
{
	struct pet *pet = (struct pet *)rawpet;

	if (petlen != sizeof(*pet))
		goto out;

	dev_dbg(&skb->dev->dev, ">> rx_handler %u bytes\n", skb->len);
	dev_dbg(&skb->dev->dev, "   RX PET: size %lu, etherType %04X, syndrome %02x\n",
		sizeof(*pet), be16_to_cpu(pet->ethertype), pet->syndrome);

	if (pet->syndrome != 48) {
		dev_dbg(&skb->dev->dev, "unexpected pet syndrome %d\n",
			pet->syndrome);
		goto out;
	}

out:
	return skb;
}

/* Must hold mlx_tls_mutex to call this function.
 * Assumes that dev->core_ctx is destroyed be the caller
 */
static void mlx_tls_free(struct mlx_tls_dev *dev)
{
	list_del(&dev->accel_dev_list);
#if IS_ENABLED(CONFIG_MLX5_CORE_FPGA_QP_SIM)
#ifdef MLX_TLS_SADB_RDMA
	kobject_put(&dev->kobj);
#endif
#endif
	/* TODO - Test the corner case of removing the last reference
	 * while receiving packets that should be handled by the rx_handler.
	 * Do we need some sync here?
	 * TODO - How do we make sure that all packets inflight are dropped?
	 */
	dev_put(dev->netdev);
	kfree(dev);
}

int mlx_tls_netdev_event(struct notifier_block *this, unsigned long event,
			 void *ptr)
{
	struct net_device *netdev = netdev_notifier_info_to_dev(ptr);
	struct mlx_tls_dev *accel_dev = NULL;

	if (!netdev)
		goto out;

	pr_debug("mlx_tls_netdev_event: %lu\n", event);

	/* We are interested only in net devices going down */
	if (event != NETDEV_UNREGISTER)
		goto out;

	/* Take down all connections using a netdev that is going down */
	mutex_lock(&mlx_tls_mutex);
	accel_dev = find_mlx_tls_dev_by_netdev(netdev);
	if (!accel_dev) {
		pr_debug("mlx_tls_netdev_event: Failed to find tls device for net device\n");
		goto unlock;
	}
	mlx_tls_free(accel_dev);

unlock:
	mutex_unlock(&mlx_tls_mutex);
out:
	return NOTIFY_DONE;
}

static struct mlx5_accel_ops mlx_tls_client_ops = {
	.rx_handler   = mlx_tls_rx_handler,
	.tx_handler   = mlx_tls_tx_handler,
	.feature_chk  = mlx_tls_feature_chk,
	.get_count = mlx_tls_get_count,
	.get_strings = mlx_tls_get_strings,
	.get_stats = mlx_tls_get_stats,
	.mtu_extra = sizeof(struct pet),
	.features = 0,
};

int mlx_tls_add_one(struct mlx_accel_core_device *accel_device)
{
	int ret = 0;
	struct mlx_tls_dev *dev = NULL;
	struct net_device *netdev = NULL;
#ifdef MLX_TLS_SADB_RDMA
	struct mlx_accel_core_conn_init_attr init_attr = {0};
#endif
	pr_debug("mlx_tls_add_one called for %s\n", accel_device->name);

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev) {
		ret = -ENOMEM;
		goto out;
	}

	INIT_LIST_HEAD(&dev->accel_dev_list);
	dev->accel_device = accel_device;
	ida_init(&dev->swid_ida);

#ifdef MLX_TLS_SADB_RDMA
	/* TODO: Move these constants to a header */
	init_attr.rx_size = 128;
	init_attr.tx_size = 32;
	init_attr.recv_cb = mlx_tls_hw_qp_recv_cb;
	init_attr.cb_arg = dev;
	dev->conn = mlx_accel_core_conn_create(accel_device, &init_attr);
	if (IS_ERR(dev->conn)) {
		ret = PTR_ERR(dev->conn);
		pr_err("mlx_tls_add_one(): Got error while creating connection %d\n",
		       ret);
		goto err_dev;
	}
#endif
	netdev = accel_device->ib_dev->get_netdev(accel_device->ib_dev,
			accel_device->port);
	if (!netdev) {
		pr_err("mlx_tls_add_one(): Failed to retrieve net device from ib device\n");
		ret = -EINVAL;
		goto err_conn;
	}
	dev->netdev = netdev;

	ret = mlx_accel_core_client_ops_register(accel_device,
						 &mlx_tls_client_ops);
	if (ret) {
		pr_err("mlx_tls_add_one(): Failed to register client ops %d\n",
		       ret);
		goto err_netdev;
	}

#if IS_ENABLED(CONFIG_MLX5_CORE_FPGA_QP_SIM)
#ifdef MLX_TLS_SADB_RDMA
	ret = tls_sysfs_init_and_add(&dev->kobj,
				     mlx_accel_core_kobj(dev->accel_device),
				     "%s",
				     "accel_dev");
	if (ret) {
		pr_err("mlx_tls_add_one(): Got error from kobject_init_and_add %d\n",
		       ret);
		goto err_ops_register;
	}
#endif
#endif

	mutex_lock(&mlx_tls_mutex);
	list_add(&dev->accel_dev_list, &mlx_tls_devs);
	mutex_unlock(&mlx_tls_mutex);

	dev->netdev->tlsdev_ops = &mlx_tls_ops;
	goto out;

#if IS_ENABLED(CONFIG_MLX5_CORE_FPGA_QP_SIM)
#ifdef MLX_TLS_SADB_RDMA
err_ops_register:
	mlx_accel_core_client_ops_unregister(accel_device);
#endif
#endif
err_netdev:
	dev_put(netdev);
err_conn:
	mlx_accel_core_conn_destroy(dev->conn);
#ifdef MLX_TLS_SADB_RDMA
err_dev:
#endif
	kfree(dev);
out:
	return ret;
}

void mlx_tls_remove_one(struct mlx_accel_core_device *accel_device)
{
	struct mlx_tls_dev *dev;
	struct net_device *netdev = NULL;

	pr_debug("mlx_tls_remove_one called for %s\n", accel_device->name);

	mutex_lock(&mlx_tls_mutex);

	list_for_each_entry(dev, &mlx_tls_devs, accel_dev_list) {
		if (dev->accel_device == accel_device) {
			netdev = dev->netdev;
			netdev->tlsdev_ops = NULL;
			mlx_accel_core_client_ops_unregister(accel_device);
#ifdef MLX_TLS_SADB_RDMA
			mlx_accel_core_conn_destroy(dev->conn);
#endif
			mlx_tls_free(dev);
			break;
		}
	}
	mutex_unlock(&mlx_tls_mutex);
}
