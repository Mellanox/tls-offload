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

#include "en_accel/tls.h"
#include "en_accel/tls_rxtx.h"

#define SYNDROME_OFFLOAD_REQUIRED 32
#define SYNDROME_SYNC 33.
#define SYNDROME_BYPASS 34

#define MIN_BYPASS_RECORD_SIZE 29
#define BYPASS_RECORD_PADDING_SIZE \
		(MIN_BYPASS_RECORD_SIZE - TLS_HEADER_SIZE)

#define MAX_BYPASS_SIZE ((1 << 15) - BYPASS_RECORD_PADDING_SIZE -\
			 TLS_HEADER_SIZE - 1)

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

#define MLX5E_METADATA_ETHER_TYPE (0x8CE4)

struct send_pet_content {
	/* The next field is meaningful only for sync packets with LSO
	 * enabled (by the syndrome field))
	 */
	__be16 first_seq;	/* LSBs of the first TCP seq in the packet */
	unsigned char sid[3];
} __packed;

struct mlx5e_tls_metadata {
	unsigned char syndrome;
	union {
		unsigned char raw[5];
		/* from host to FPGA */
		struct send_pet_content send;
	} __packed content;
	/* packet type ID field	*/
	__be16 ethertype;
} __packed;

static int insert_pet(struct sk_buff *skb)
{
	struct ethhdr *eth;
	struct mlx5e_tls_metadata *pet;
	struct mlx_tls_offload_context *context;
	char *swid;

	pr_debug("insert_pet started\n");
	if (skb_cow_head(skb, sizeof(struct mlx5e_tls_metadata)))
		return -ENOMEM;

	eth = (struct ethhdr *)skb_push(skb, sizeof(struct mlx5e_tls_metadata));
	skb->mac_header -= sizeof(struct mlx5e_tls_metadata);
	pet = (struct mlx5e_tls_metadata *)(eth + 1);

	memmove(skb->data, skb->data + sizeof(struct mlx5e_tls_metadata), 2 * ETH_ALEN);

	eth->h_proto = cpu_to_be16(MLX5E_METADATA_ETHER_TYPE);
	pet->syndrome = SYNDROME_OFFLOAD_REQUIRED;

	memset(pet->content.raw, 0, sizeof(pet->content.raw));
	context = get_tls_context(skb->sk);

	swid = (char*)&context->swid;
	swid += sizeof(context->swid) - sizeof(pet->content.send.sid);
	memcpy(pet->content.send.sid, swid, sizeof(pet->content.send.sid));

	return 0;
}

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

static void send_sync_skb(
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
	struct mlx5e_tls_metadata *pet;
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

	pet = (struct mlx5e_tls_metadata *)(nskb->data + sizeof(struct ethhdr));
	pet->syndrome = syndrome;
	memcpy(pet->content.raw, &tcp_seq_low, sizeof(tcp_seq_low));

	nskb->ip_summed = CHECKSUM_PARTIAL;
	__skb_pull(nskb, skb_transport_offset(skb));
	inet_csk(skb->sk)->icsk_af_ops->send_check(skb->sk, nskb);
	__skb_push(nskb, skb_transport_offset(skb));

	nskb->xmit_more = 1;
	nskb->queue_mapping = skb->queue_mapping;
	pr_debug("Sending sync packet");
	skb->dev->netdev_ops->ndo_start_xmit(nskb, skb->dev);
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

	if (get_sync_data(context, tcp_seq, &info))
		goto err_out;

	if (unlikely(info.sync_len < 0)) {
		headln = skb_transport_offset(skb) + tcp_hdrlen(skb);
		if (-info.sync_len > MAX_BYPASS_SIZE) {
			if (skb->len - headln > -info.sync_len) {
				pr_err("Required bypass record is too big\n");
				/* can fragment into two large SKBs in SW */
				return NULL;
			}
			pr_debug("Can't bypass, sending orig skb\n");
			return skb;
		}

		linear_len = MIN_BYPASS_RECORD_SIZE;
	}

	if (unlikely(insert_pet(skb)))
		goto err_out;

	headln = skb_transport_offset(skb) + tcp_hdrlen(skb);
	linear_len += headln;
	nskb = alloc_skb(linear_len, GFP_ATOMIC);
	if (unlikely(!nskb))
		goto err_out;

	context->context.expected_seq = tcp_seq + skb->len - headln;
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

	send_sync_skb(skb, nskb, tcp_seq, headln, syndrome);
	return skb;

err_out:
	dev_kfree_skb_any(skb);
	return NULL;
}

struct sk_buff *mlx5e_tls_handle_tx_skb(struct net_device *netdev,
					struct mlx5e_tx_wqe *wqe,
					struct sk_buff *skb)
{
	struct mlx_tls_offload_context *context;
	int datalen;
	u32 skb_seq;
	u32 expected_seq;

	pr_debug("mlx_tls_tx_handler started\n");

	if (!skb->sk || !tls_is_sk_tx_device_offloaded(skb->sk))
		goto out;

	datalen = skb->len - (skb_transport_offset(skb) + tcp_hdrlen(skb));
	if (!datalen)
		goto out;

	skb_seq =  ntohl(tcp_hdr(skb)->seq);

	context = get_tls_context(skb->sk);
	expected_seq = context->context.expected_seq;

	pr_debug("mlx_tls_tx_handler: mapping: %u cpu %u size %u with swid %u expectedSN: %u actualSN: %u\n",
		 skb->queue_mapping, smp_processor_id(), skb->len,
		 ntohl(context->swid), expected_seq, skb_seq);

	if (unlikely(expected_seq != skb_seq)) {
		pr_debug("out of order\n");
		skb = handle_ooo(context, skb);
		goto out;
	}

	if (unlikely(insert_pet(skb))) {
		dev_kfree_skb_any(skb);
		skb = NULL;
		goto out;
	}

	context->context.expected_seq = skb_seq + datalen;
out:
	return skb;
}
