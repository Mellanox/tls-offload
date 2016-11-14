/*
 * IPV6 GSO/GRO offload support
 * Linux INET implementation
 *
 * Copyright (C) 2016 secunet Security Networks AG
 * Author: Steffen Klassert <steffen.klassert@secunet.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * ESP GRO support
 */

#include <linux/skbuff.h>
#include <linux/init.h>
#include <net/protocol.h>
#include <crypto/aead.h>
#include <crypto/authenc.h>
#include <linux/err.h>
#include <linux/module.h>
#include <net/ip.h>
#include <net/xfrm.h>
#include <net/esp.h>
#include <linux/scatterlist.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <net/ip6_route.h>
#include <net/ipv6.h>
#include <linux/icmpv6.h>

static struct sk_buff **esp6_gro_receive(struct sk_buff **head,
					 struct sk_buff *skb)
{
	int err;
	if (NAPI_GRO_CB(skb)->flush)
		goto out;

	skb_pull(skb, skb_gro_offset(skb));
	skb->xfrm_gro = 1;

	XFRM_SPI_SKB_CB(skb)->family = AF_INET6;
	XFRM_SPI_SKB_CB(skb)->daddroff = offsetof(struct ipv6hdr, daddr);
	err = xfrm_input(skb, IPPROTO_ESP, 0, -2);
	if (err == -EOPNOTSUPP) {
		skb_push(skb, skb_gro_offset(skb));
		NAPI_GRO_CB(skb)->same_flow = 0;
		NAPI_GRO_CB(skb)->flush = 1;
		skb->xfrm_gro = 0;
		goto out;
	}

	return ERR_PTR(-EINPROGRESS);
out:
	return NULL;
}

static int esp6_gro_complete(struct sk_buff *skb, int nhoff)
{
	struct xfrm_state *x = xfrm_input_state(skb);
	struct crypto_aead *aead = x->data;
	struct ip_esp_hdr *esph = (struct ip_esp_hdr *)(skb->data + nhoff);
	struct packet_offload *ptype;
	int err = -ENOENT;
	__be16 type = skb->protocol;

	rcu_read_lock();
	ptype = gro_find_complete_by_type(type);
	if (ptype != NULL)
		err = ptype->callbacks.gro_complete(skb, nhoff + sizeof(*esph) + crypto_aead_ivsize(aead));

	rcu_read_unlock();

	return err;
}

static int esp6_input_tail(struct xfrm_state *x, struct sk_buff *skb)
{
	struct crypto_aead *aead = x->data;

	if (!pskb_may_pull(skb, sizeof(struct ip_esp_hdr) + crypto_aead_ivsize(aead)))
		return -EINVAL;

	skb->ip_summed = CHECKSUM_NONE;

	return esp6_input_done2(skb, 0);
}

static int esp6_xmit(struct xfrm_state *x, struct sk_buff *skb,  netdev_features_t features)
{
	int err;
	int clen;
	int alen;
	int plen;
	int tfclen;
	int nfrags;
	int tailen;
	__u8 proto;
	int blksize;
	__be64 seqno;
	struct xfrm_offload *xo;
	struct ip_esp_hdr *esph;
	struct crypto_aead *aead;
	bool inplace = true;

	xo = xfrm_offload(skb);

	if (!xo)
		return -EINVAL;

	if (!(features & NETIF_F_HW_ESP) ||
	    (x->xso.offload_handle &&  x->xso.dev != skb->dev)) {
		xo->flags |= CRYPTO_FALLBACK;
	}

	proto = xo->proto;

	/* skb is pure payload to encrypt */

	aead = x->data;
	alen = crypto_aead_authsize(aead);

	tfclen = 0;
	/* XXX: Add support for tfc padding here. */

	blksize = ALIGN(crypto_aead_blocksize(aead), 4);
	clen = ALIGN(skb->len + 2 + tfclen, blksize);
	plen = clen - skb->len - tfclen;
	tailen = tfclen + plen + alen;

	nfrags = esp6_output_head(x, skb, proto, tfclen, tailen, plen, &inplace);
	if (nfrags < 0)
		return nfrags;

	esph = ip_esp_hdr(skb);
	esph->spi = x->id.spi;

	skb_push(skb, -skb_network_offset(skb));

	if (xo->flags & XFRM_GSO_SEGMENT) {
		esph->seq_no = htonl(xo->seq.low);
	} else {
		int len;

		len = skb->len - sizeof(struct ipv6hdr);
		if (len > IPV6_MAXPLEN)
			len = 0;

		ipv6_hdr(skb)->payload_len = htons(len);
	}

	if (x->xso.offload_handle && !(xo->flags & CRYPTO_FALLBACK))
		return 0;

	seqno = cpu_to_be64(xo->seq.low + ((u64)xo->seq.hi << 32));

	err = esp6_output_tail(x, skb, seqno, clen, nfrags, inplace);
	if (err < 0)
		return err;

	secpath_reset(skb);

	return 0;
}

static const struct net_offload esp6_offload = {
	.callbacks = {
		.gro_receive = esp6_gro_receive,
		.gro_complete = esp6_gro_complete,
	},
};

static const struct xfrm_type_offload esp6_type_offload = {
	.description	= "ESP6 OFFLOAD",
	.owner		= THIS_MODULE,
	.proto	     	= IPPROTO_ESP,
	.input_tail	= esp6_input_tail,
	.xmit		= esp6_xmit,
};

static int __init esp6_offload_init(void)
{
	if (xfrm_register_type_offload(&esp6_type_offload, AF_INET6) < 0) {
		pr_info("%s: can't add xfrm type offload\n", __func__);
		return -EAGAIN;
	}

	return inet6_add_offload(&esp6_offload, IPPROTO_ESP);
}

static void __exit esp6_offload_exit(void)
{
	if (xfrm_unregister_type_offload(&esp6_type_offload, AF_INET6) < 0)
		pr_info("%s: can't remove xfrm type offload\n", __func__);

	inet6_del_offload(&esp6_offload, IPPROTO_ESP);
}

module_init(esp6_offload_init);
module_exit(esp6_offload_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Steffen Klassert <steffen.klassert@secunet.com>");
