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
 * This file adds a sysctrl interface as bellow:
 * /proc/
 *	`-- sys/
 *		`-- net/
 *			`-- l3_firewall_cache_ctrl/
 *					`-- ipv4_l3_firewall_cache_enable
 *
 * In order to enable or disable the acceleration function dynamically
 * by the following command:
 * enable:
 * sysctl -w net.l3_firewall_cache_ctrl.ipv4_l3_firewall_cache_enable=1
 * or
 * echo 1 >/proc/sys/net/l3_firewall_cache_ctrl/ipv4_l3_firewall_cache_enable
 *
 * disable:
 * sysctl -w net.l3_firewall_cache_ctrl.ipv4_l3_firewall_cache_enable=0
 * or
 * echo 0 >/proc/sys/net/l3_firewall_cache_ctrl/ipv4_l3_firewall_cache_enable
 *
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
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/unistd.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/sysctl.h>
#include <linux/version.h>
#include <linux/proc_fs.h>

int ipv4_l3_firewall_cache_enable;
EXPORT_SYMBOL(ipv4_l3_firewall_cache_enable);

static struct ctl_table_header *L3_Firewall_Cache_Header;

static int proc_ipv4_l3_firewall_cache_enable(ctl_table *ctl, int write,
				void __user *buffer,
				size_t *lenp, loff_t *ppos)
{
	int old_state = ipv4_l3_firewall_cache_enable, ret;
	ret = proc_dointvec(ctl, write, buffer, lenp, ppos);
	if (ipv4_l3_firewall_cache_enable != 0)
		ipv4_l3_firewall_cache_enable = 1;

	if (ipv4_l3_firewall_cache_enable != old_state) {
		if (ipv4_l3_firewall_cache_enable)
			printk(KERN_INFO "IPv4 Firewall acceleration function"
					" based on Cache enabled.\n");
		else
			printk(KERN_INFO "IPv4 Firewall acceleration function"
					" based on Cache disabled.\n");
	}
	return ret;
}

static struct ctl_table L3_Firewall_Cache_Items[] = {
	{
		.procname       = "ipv4_l3_firewall_cache_enable",
		.data           = &ipv4_l3_firewall_cache_enable,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = proc_ipv4_l3_firewall_cache_enable,
	},
	{}
};
static struct ctl_table L3_Firewall_Cache_Directory[] = {
	{
		.procname       = "l3_firewall_cache_ctrl",
		.mode           = 0555,
		.child          = L3_Firewall_Cache_Items,
	},
	{}
};

static struct ctl_path L3_Firewall_Cache_Path_Root[] = {
	{
		.procname = "net",
	},
	{}
};

int L3_Firewall_Cache_register_proc(void)
{
	L3_Firewall_Cache_Header = register_sysctl_paths(
		L3_Firewall_Cache_Path_Root,
		L3_Firewall_Cache_Directory);

	if (!L3_Firewall_Cache_Header)
		return -ENOMEM;
	return 0;
}
EXPORT_SYMBOL(L3_Firewall_Cache_register_proc);

int L3_Firewall_Cache_unregister_proc(void)
{
	if (L3_Firewall_Cache_Header)
		unregister_sysctl_table(L3_Firewall_Cache_Header);
	return 0;
}
EXPORT_SYMBOL(L3_Firewall_Cache_unregister_proc);
