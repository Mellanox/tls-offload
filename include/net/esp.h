#ifndef _NET_ESP_H
#define _NET_ESP_H

#include <linux/skbuff.h>

struct ip_esp_hdr;

static inline struct ip_esp_hdr *ip_esp_hdr(const struct sk_buff *skb)
{
	return (struct ip_esp_hdr *)skb_transport_header(skb);
}

int esp_output_head(struct xfrm_state *x, struct sk_buff *skb, __u8 proto, int tfclen, int tailen, int plen, bool *inplace);
int esp_output_tail(struct xfrm_state *x, struct sk_buff *skb, __be64 seqno, int clen, int nfrags, bool inplace);
int esp_input_done2(struct sk_buff *skb, int err);
#endif
