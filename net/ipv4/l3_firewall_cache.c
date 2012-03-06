/*
 * This is a module which is used for L3 Firewall acceleration
 *
 * This module adds a soft cache table whose data structure is based
 * on ring buffer. Each cache line includes all of the fields which
 * is needed by Firewall rule-set basic filtering features.
 * When a new IP packet comes,it will go along the original filtering
 * path, then a message of the IP packet can be sent to the cache so
 * that the cache can remember the IP packet as an acquaintance, and
 * the action in the original filter path will be recorded either.
 * When another IP packet comes, it is searched in the cache firstly
 * and then it will be judged whether it is an acquainted IP packet
 * or not. If hit, in another word, if it is an acquainted IP packet,
 * it will take the last action recorded in the cache table, but it
 * does not need to go along the old boring filtering path.
 *
 * Copyright (C) 2012 Freescale Semiconductor, Inc. All rights reserved.
 *
 * Authors: Jianhua Xie <jianhua.xie@freescale.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/netdevice.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/netfilter_ipv4.h>
#include <net/checksum.h>
#include <linux/route.h>
#include <net/route.h>
#include <net/xfrm.h>

#include <linux/l3_firewall_cache.h>
#include <linux/netfilter/x_tables.h>
#include <linux/etherdevice.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jianhua Xie <jianhua.xie@freescale.com>");
MODULE_DESCRIPTION("L3 Firewall accelorator");

#ifdef CONFIG_L3_FIREWALL_CACHE

struct p_firewall_cache *p_l3_firewall_cache;
EXPORT_SYMBOL_GPL(p_l3_firewall_cache);

int init_l3_firewall_cache()
{
	memset(p_l3_firewall_cache->cache_lines,
		0, sizeof(struct firewall_cache_lines) * TOTAL_LINES_OF_CACHE);
	p_l3_firewall_cache->current = -1; /* empty */
	p_l3_firewall_cache->total = 0;
	p_l3_firewall_cache->full = 0; /* full flag is faulse */

	return 0;
}
EXPORT_SYMBOL_GPL(init_l3_firewall_cache);


/* update_l3_firewall_cache- update a message to the cache
 *
 * @pf:			NFPROTO_IPV4
 * @hook:		NF_INET_FORWARD
 * @skb:		the current packet
 * @indev:		where the packet comes from
 * @outdev:		where the packet will go to
 * @p_l3_firewall_cache:	cache address
 * @response:	the last action of Netfilter
 *
 * Record a new ip packet and the netfilter's response then insert
 * them to the top cache line, including, the net device which the
 * packet comes from and go to.
 *
 * The function returns 0 forever.
 */
int update_l3_firewall_cache(u_int8_t pf,
			unsigned int hook,
			struct sk_buff *skb,
			struct net_device *indev,
			struct net_device *outdev,
			struct p_firewall_cache *p_l3_firewall_cache,
			unsigned int response)
{
	unsigned long current_pos = 0;
	struct firewall_cache_lines *p = (struct firewall_cache_lines *)
		&(p_l3_firewall_cache->cache_lines[0]);
	/* don't need to update cache while disable the function */
	if (ipv4_l3_firewall_cache_enable == 0)
		return 0;
	/* we only cache IPV4 and Forwarding */
	if (NFPROTO_IPV4 != pf)
		return 0;
	if (NF_INET_FORWARD != hook)
		return 0;
	/* we only cache TCP/UDP protocol, others go the slow path */
	if ((IPPROTO_TCP != ip_hdr(skb)->protocol) &&
		(IPPROTO_UDP != ip_hdr(skb)->protocol))
			return 0;
	/* we only cache NF_STOP/NF_DROP/NF_ACCEPT actions */
	if ((NF_DROP != response) && (NF_STOP != response) &&
		(NF_ACCEPT != response))
			return 0;
	write_lock_bh(&(p_l3_firewall_cache->lock));
	/* calculate current pointer and juge ring buff full flag */
	p_l3_firewall_cache->total++;
	if (p_l3_firewall_cache->total >= TOTAL_LINES_OF_CACHE)
		p_l3_firewall_cache->full = 1;
	/* process overflow */
	if (p_l3_firewall_cache->total < 0)
		p_l3_firewall_cache->total = 0;
	p_l3_firewall_cache->current =
		(p_l3_firewall_cache->current + 1) & (TOTAL_LINES_OF_CACHE - 1);

	current_pos = p_l3_firewall_cache->current;
	memcpy(p[current_pos].h_source, eth_hdr(skb)->h_source, ETH_ALEN);
	p[current_pos].Saddr	= ip_hdr(skb)->saddr;
	p[current_pos].Daddr	= ip_hdr(skb)->daddr;
	p[current_pos].Protocol	= ip_hdr(skb)->protocol;
	p[current_pos].response	= response;

	if (IPPROTO_TCP == ip_hdr(skb)->protocol) {
		p[current_pos].SourcePort	= tcp_hdr(skb)->source;
		p[current_pos].DestPort		= tcp_hdr(skb)->dest;
	} else if (IPPROTO_UDP == ip_hdr(skb)->protocol) {
		p[current_pos].SourcePort	= udp_hdr(skb)->source;
		p[current_pos].DestPort		= udp_hdr(skb)->dest;
	}
	write_unlock_bh(&(p_l3_firewall_cache->lock));
	return 0;
}
EXPORT_SYMBOL_GPL(update_l3_firewall_cache);

/* search_from_firewall_cache- search a skb from the cache
 *
 * @pf:			NFPROTO_IPV4
 * @hook:		NF_INET_FORWARD
 * @skb:		the current packet
 * @indev:		where the packet comes from
 * @outdev:		where the packet will go to
 * @p_l3_firewall_cache:	cache address
 *
 * Search a new ip packet from the cache, if it is found,
 * the function returns the response in the same cache line,
 * else it returns NF_NOTFOUND.
 */
int search_from_firewall_cache(u_int8_t pf,
			unsigned int hook,
			struct sk_buff *skb,
			struct net_device *indev,
			struct net_device *outdev,
			struct p_firewall_cache *p_l3_firewall_cache)
{
	bool found = false;
	int i;

	/* NF_DROP=0, NF_ACCEPT=1, NF_STOP=5 */
	unsigned int response = NF_NOTFOUND;
	struct ethhdr *mh = eth_hdr(skb);

	unsigned char   ms[ETH_ALEN]; /* Source MAC */
	__u8    lpro;	/* protocol */
	__be32  lsa;	/* source address */
	__be32  lda;	/* destination address */
	__be16  lsp;	/* source port */
	__be16  ldp;	/* destination port */

	struct firewall_cache_lines *p = (struct firewall_cache_lines *)
		&(p_l3_firewall_cache->cache_lines[0]);
	/* don't use the cache while disable the function */
	if (ipv4_l3_firewall_cache_enable == 0)
		return NF_NOTFOUND;
	/* we only cache IPV4 and Forwarding */
	if (NFPROTO_IPV4 != pf)
		return NF_NOTFOUND;
	if (NF_INET_FORWARD != hook)
		return NF_NOTFOUND;
	/* we only search TCP/UDP protocol, others go the slow path */
	if ((IPPROTO_TCP != ip_hdr(skb)->protocol) &&
		(IPPROTO_UDP != ip_hdr(skb)->protocol))
		return NF_NOTFOUND;
	if (0 == p_l3_firewall_cache->total)
		return NF_NOTFOUND; /* empty table, need not to search */

	/* store the ip pkg's chractors */
	memcpy(ms, mh->h_source, ETH_ALEN);
	lpro	= ip_hdr(skb)->protocol;
	lsa		= ip_hdr(skb)->saddr;
	lda		= ip_hdr(skb)->daddr;
	if (IPPROTO_TCP == ip_hdr(skb)->protocol) {
		lsp		= tcp_hdr(skb)->source;
		ldp		= tcp_hdr(skb)->dest;
	} else{
		lsp		= udp_hdr(skb)->source;
		ldp		= udp_hdr(skb)->dest;
	}

	/* if tables is not full,loop from current till head.
	 * if find, return with the response of current pointer.
	 * else if not find, return NF_NOTFOUND */
	if (!(p_l3_firewall_cache->full)) {
		read_lock_bh(&(p_l3_firewall_cache->lock));
		for (i = p_l3_firewall_cache->current; i >= 0; i--) {
			if ((!compare_ether_addr(p[i].h_source, ms)) &&
				(p[i].Saddr == lsa) &&
				(p[i].Daddr == lda) &&
				(p[i].Protocol == lpro) &&
				(p[i].SourcePort == lsp) &&
				(p[i].DestPort == ldp)) {

				response = p[i].response;
				read_unlock_bh(&(p_l3_firewall_cache->lock));
				found = true;
				goto out;
			}
		}
		read_unlock_bh(&(p_l3_firewall_cache->lock));
	} else {
	/* if table is full, loop from current to head,
	 * then loop from tail to current pointer again.
	 * if find, return with the response of current pointer.
	 * else if not find, return NF_NOTFOUND */
		read_lock_bh(&(p_l3_firewall_cache->lock));
		i = p_l3_firewall_cache->current;
		for (;;) {
			/* find from current pointer */
			if ((!compare_ether_addr(p[i].h_source, ms)) &&
				(p[i].Saddr == lsa) &&
				(p[i].Daddr == lda) &&
				(p[i].Protocol == lpro) &&
				(p[i].SourcePort == lsp) &&
				(p[i].DestPort == ldp)) {

				response = p[i].response;
				read_unlock_bh(&(p_l3_firewall_cache->lock));
				found = true;
				goto out;
				} else {
					/* adjust the pointer and make sure
					 * to travel all the cache lines.
					 */
					i = (TOTAL_LINES_OF_CACHE + i - 1) &
						(TOTAL_LINES_OF_CACHE - 1);
					if (p_l3_firewall_cache->current == i)
						break;
				}
		}
		read_unlock_bh(&(p_l3_firewall_cache->lock));
	}

out:
	/* if not found, the response is NF_NOTFOUND */
	return (int)response;
}
EXPORT_SYMBOL_GPL(search_from_firewall_cache);

static int __init l3_firewall_cache_init_early(void)
{
	/* set l3 firewall cahche disable as default */
	ipv4_l3_firewall_cache_enable = 0;
	p_l3_firewall_cache = (struct p_firewall_cache *)
		kmalloc(sizeof(struct p_firewall_cache), GFP_KERNEL);
	if (!p_l3_firewall_cache)
		return -ENOMEM;
	if (init_l3_firewall_cache()) {
		kfree(p_l3_firewall_cache);
		printk(KERN_INFO "%s:not enough memory.\n", __func__);
		return -ENOMEM;
	}
	rwlock_init(&(p_l3_firewall_cache->lock));
	printk(KERN_INFO
		"%s:init ok\nTOTAL_LINES_OF_CACHE:%d, struct size:%dB\n",
		__func__, TOTAL_LINES_OF_CACHE,
		sizeof(struct firewall_cache_lines));

	L3_Firewall_Cache_register_proc();
	return 0;
}

static void __exit l3_firewall_cache_exit(void)
{
	kfree(p_l3_firewall_cache);
	printk(KERN_INFO "%s exit ok\n.", __func__);
	L3_Firewall_Cache_unregister_proc();
}

module_init(l3_firewall_cache_init_early);
module_exit(l3_firewall_cache_exit);

#endif /* end CONFIG_L3_FIREWALL_CACHE */
