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
#ifndef	__H_L3_FIREWALL_CACHE_H__
#define	__H_L3_FIREWALL_CACHE_H__

#include <linux/spinlock.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>

#ifdef CONFIG_L3_FIREWALL_CACHE

#define TOTAL_LINES_OF_CACHE 0x400
#define NF_NOTFOUND	-1

/* cache line members come from the the requirement of
 * Firewall rule-set basic filtering features. please refer
 * to http://en.wikipedia.org/wiki/Comparison_of_firewalls
 */
struct firewall_cache_lines {
	unsigned char	h_source[ETH_ALEN];	/* Source MAC */
	__u8	Protocol;		/* L3 protocol: TCP/UDP */
	__be32	Saddr;			/* Source IP address */
	__be32	Daddr;			/* Destination IP address */
	__be16	SourcePort;		/* Source Port */
	__be16	DestPort;		/* Destination Port */
	unsigned int response;		/* Response from hook functions.*/
};

struct p_firewall_cache {
	struct firewall_cache_lines cache_lines[TOTAL_LINES_OF_CACHE];
	rwlock_t    lock;
	int			current;/* avoid to search from the head */
	int			total;
	int			full;
};

extern struct p_firewall_cache *p_l3_firewall_cache;

/* The L3 Firewall sysctrl variable,1: enable, 0: disable */
extern int	ipv4_l3_firewall_cache_enable;
extern int	L3_Firewall_Cache_register_proc(void);
extern int	L3_Firewall_Cache_unregister_proc(void);

int init_l3_firewall_cache(void);

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
			unsigned int response);

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
			struct p_firewall_cache *p_l3_firewall_cache);

#endif	/* endif CONFIG_L3_FIREWALL_CACHE */
#endif	/* endif __H_L3_FIREWALL_CACHE_H__ */
