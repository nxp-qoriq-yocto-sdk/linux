/*
 * Copyright (C) 2010 Freescale Semiconductor, Inc. All rights reserved.
 *
 * Author: Varun Sethi <Varun.Sethi@freescale.com>
 *
 * Description:
 * This file is derived from arch/powerpc/include/asm/kvm_e500.h,
 * by Yu Liu, <yu.liu@freescale.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2, as
 * published by the Free Software Foundation.
 */

#ifndef __ASM_KVM_E500MC_H__
#define __ASM_KVM_E500MC_H__

#include <linux/kvm_host.h>

#define BOOKE_INTERRUPT_SIZE 36

#define E500MC_TLB_NUM   2

#define E500MC_TLB_VALID 1
#define E500MC_TLB_DIRTY 2

struct tlbe_priv {
	pfn_t pfn;
	unsigned int flags; /* E500MC_TLB_* */
	/* bitmap of h/w tlbe's mapped by this gtlbe, numbered from lsb */
	u64 hw_tlbe_bitmap;
};

struct kvmppc_vcpu_e500mc {
	/* Unmodified copy of the guest's TLB -- shared with Qemu. */
	struct kvm_book3e_206_tlb_entry *gtlb_arch;

	/* Starting entry number in gtlb_arch[] */
	int gtlb_offset[E500MC_TLB_NUM];

	/* KVM internal information associated with each guest TLB entry */
	struct tlbe_priv *gtlb_priv[E500MC_TLB_NUM];

	/*
	 * h/w tlbe to gtlbe reverse map - used for tlb1 invalidation.
	 * This is an array of same size of number of host tlbe's that
	 * points to an index into the guest tlb, basically used to reverse
	 * map a h/w tlbe to the gtlbe for which it is being used for.
	 */
	unsigned int *rmap_gtlbe;

	unsigned int gtlb_size[E500MC_TLB_NUM];
	unsigned int gtlb_nv[E500MC_TLB_NUM];

	unsigned int gtlb0_ways;
	unsigned int gtlb0_sets;

	u32 oldpir;

	u32 pid;
	u32 svr;

	u32 mmucfg;
	u32 l1csr0;
	u32 l1csr1;
	u32 hid0;
	u32 hid1;
	u32 tlb0cfg;
	u32 tlb1cfg;
	u64 mcar;

	struct page **shared_tlb_pages;
	int num_shared_tlb_pages;

	u32 epcr;
	u32 msrp;
	u32 lpid;
	u32 eplc;
	u32 epsc;
	u32 gpir;
	u32 gesr;
	u32 gepr;

	struct kvm_vcpu vcpu;
};

static inline struct kvmppc_vcpu_e500mc *to_e500mc(struct kvm_vcpu *vcpu)
{
	return container_of(vcpu, struct kvmppc_vcpu_e500mc, vcpu);
}

#endif /* __ASM_KVM_E500MC_H__ */
