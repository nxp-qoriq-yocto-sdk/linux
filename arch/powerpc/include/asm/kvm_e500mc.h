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

struct tlbe{
	u32 mas1;
	u32 mas2;
	u32 mas3;
	u32 mas7;
	u32 mas8;
};

struct kvmppc_vcpu_e500mc {
	/* Unmodified copy of the guest's TLB. */
	struct tlbe *guest_tlb[E500MC_TLB_NUM];
	/* TLB that's actually used when the guest is running. */
	struct tlbe *shadow_tlb[E500MC_TLB_NUM];

	unsigned int guest_tlb_size[E500MC_TLB_NUM];
	unsigned int shadow_tlb_size[E500MC_TLB_NUM];
	unsigned int guest_tlb_nv[E500MC_TLB_NUM];

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

	u32 epcr;
	u32 msrp;
	u32 lpid;
	u32 eplc;
	u32 epsc;
	u32 gpir;
	u32 gesr;
	u32 gepr;
	u32 gsrr0;
	u32 gsrr1;

	struct kvm_vcpu vcpu;
};

static inline struct kvmppc_vcpu_e500mc *to_e500mc(struct kvm_vcpu *vcpu)
{
	return container_of(vcpu, struct kvmppc_vcpu_e500mc, vcpu);
}

#endif /* __ASM_KVM_E500MC_H__ */
