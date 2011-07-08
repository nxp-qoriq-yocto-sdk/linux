/*
 * Copyright (C) 2008-2011 Freescale Semiconductor, Inc. All rights reserved.
 *
 * Author: Yu Liu, <yu.liu@freescale.com>
 *
 * Description:
 * This file is derived from arch/powerpc/kvm/44x.c,
 * by Hollis Blanchard <hollisb@us.ibm.com>.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2, as
 * published by the Free Software Foundation.
 */

#include <linux/kvm_host.h>
#include <linux/slab.h>
#include <linux/err.h>

#include <asm/reg.h>
#include <asm/cputable.h>
#include <asm/tlbflush.h>
#include <asm/kvm_e500.h>
#include <asm/kvm_ppc.h>

#include "booke.h"
#include "e500_tlb.h"

void kvmppc_core_load_host_debugstate(struct kvm_vcpu *vcpu)
{
}

void kvmppc_core_load_guest_debugstate(struct kvm_vcpu *vcpu)
{
}

void kvmppc_core_vcpu_load(struct kvm_vcpu *vcpu, int cpu)
{
	current->thread.kvm_shadow_vcpu = vcpu;
	kvmppc_e500_tlb_load(vcpu, cpu);

	/* Retore the PM Registers on VCPU load */
	if (vcpu->arch.pm_is_reserved) {
		mtpmr(PMRN_PMC0, vcpu->arch.pm_reg.pmc[0]);
		mtpmr(PMRN_PMC1, vcpu->arch.pm_reg.pmc[1]);
		mtpmr(PMRN_PMC2, vcpu->arch.pm_reg.pmc[2]);
		mtpmr(PMRN_PMC3, vcpu->arch.pm_reg.pmc[3]);
		mtpmr(PMRN_PMLCB0, vcpu->arch.pm_reg.pmlcb[0]);
		mtpmr(PMRN_PMLCB1, vcpu->arch.pm_reg.pmlcb[1]);
		mtpmr(PMRN_PMLCB2, vcpu->arch.pm_reg.pmlcb[2]);
		mtpmr(PMRN_PMLCB3, vcpu->arch.pm_reg.pmlcb[3]);
		kvmppc_set_hwpmlca_all(vcpu);
		if (kvmppc_core_pending_perfmon(vcpu))
			mtpmr(PMRN_PMGC0, vcpu->arch.pm_reg.pmgc0 &
							~PMGC0_PMIE);
		else
			mtpmr(PMRN_PMGC0, vcpu->arch.pm_reg.pmgc0);

		isync();
	}
}

void kvmppc_core_vcpu_put(struct kvm_vcpu *vcpu)
{
	kvmppc_e500_tlb_put(vcpu);

#ifdef CONFIG_SPE
	if (vcpu->arch.shadow_msr & MSR_SPE)
		kvmppc_vcpu_disable_spe(vcpu);
#endif
	/* Freeze all counters and disable PM interrupt. Store the
	 * current value of PM counters before the other guest owerwrites.
	 */

	if (vcpu->arch.pm_is_reserved) {
		vcpu->arch.pm_reg.pmc[0] = mfpmr(PMRN_PMC0);
		vcpu->arch.pm_reg.pmc[1] = mfpmr(PMRN_PMC1);
		vcpu->arch.pm_reg.pmc[2] = mfpmr(PMRN_PMC2);
		vcpu->arch.pm_reg.pmc[3] = mfpmr(PMRN_PMC3);
		mtpmr(PMRN_PMGC0, PMGC0_FAC);
		isync();
	}
	current->thread.kvm_shadow_vcpu = NULL;
}

int kvmppc_core_check_processor_compat(void)
{
	int r;

	if (strcmp(cur_cpu_spec->cpu_name, "e500v2") == 0)
		r = 0;
	else
		r = -ENOTSUPP;

	return r;
}

int kvmppc_core_vcpu_setup(struct kvm_vcpu *vcpu)
{
	struct kvmppc_vcpu_e500 *vcpu_e500 = to_e500(vcpu);

	kvmppc_e500_tlb_setup(vcpu_e500);

	/* Registers init */
	vcpu->arch.pvr = mfspr(SPRN_PVR);
	vcpu_e500->svr = mfspr(SPRN_SVR);

	return 0;
}

int __kvmppc_vcpu_run(struct kvm_run *kvm_run, struct kvm_vcpu *vcpu)
{
	int ret;

	kvmppc_wdt_resume(vcpu);
	ret = __kvmppc_vcpu_entry(kvm_run, vcpu);
	kvmppc_wdt_pause(vcpu);

	return ret;
}

/* 'linear_address' is actually an encoding of AS|PID|EADDR . */
int kvmppc_core_vcpu_translate(struct kvm_vcpu *vcpu,
                               struct kvm_translation *tr)
{
	int index;
	gva_t eaddr;
	u8 pid;
	u8 as;

	eaddr = tr->linear_address;
	pid = (tr->linear_address >> 32) & 0xff;
	as = (tr->linear_address >> 40) & 0x1;

	index = kvmppc_e500_tlb_search(vcpu, eaddr, pid, as);
	if (index < 0) {
		tr->valid = 0;
		return 0;
	}

	tr->physical_address = kvmppc_mmu_xlate(vcpu, index, eaddr);
	/* XXX what does "writeable" and "usermode" even mean? */
	tr->valid = 1;

	return 0;
}

void kvmppc_core_get_sregs(struct kvm_vcpu *vcpu, struct kvm_sregs *sregs)
{
	struct kvmppc_vcpu_e500 *vcpu_e500 = to_e500(vcpu);

	sregs->u.e.features |= KVM_SREGS_E_ARCH206_MMU | KVM_SREGS_E_SPE |
	                       KVM_SREGS_E_PM;
	sregs->u.e.impl_id = KVM_SREGS_E_IMPL_FSL;

	sregs->u.e.impl.fsl.features = 0;
	sregs->u.e.impl.fsl.svr = vcpu_e500->svr;
	sregs->u.e.impl.fsl.hid0 = vcpu_e500->hid0;
	sregs->u.e.impl.fsl.mcar = vcpu_e500->mcar;

	sregs->u.e.mas0 = vcpu->arch.shared->mas0;
	sregs->u.e.mas1 = vcpu->arch.shared->mas1;
	sregs->u.e.mas2 = vcpu->arch.shared->mas2;
	sregs->u.e.mas7_3 = vcpu->arch.shared->mas7_3;
	sregs->u.e.mas4 = vcpu->arch.shared->mas4;
	sregs->u.e.mas6 = vcpu->arch.shared->mas6;

	sregs->u.e.mmucfg = kvmppc_get_mmucfg(vcpu);
	sregs->u.e.tlbcfg[0] = vcpu_e500->tlb0cfg;
	sregs->u.e.tlbcfg[1] = vcpu_e500->tlb1cfg;
	sregs->u.e.tlbcfg[2] = 0;
	sregs->u.e.tlbcfg[3] = 0;

	sregs->u.e.ivor_high[0] = vcpu->arch.ivor[BOOKE_IRQPRIO_SPE_UNAVAIL];
	sregs->u.e.ivor_high[1] = vcpu->arch.ivor[BOOKE_IRQPRIO_SPE_FP_DATA];
	sregs->u.e.ivor_high[2] = vcpu->arch.ivor[BOOKE_IRQPRIO_SPE_FP_ROUND];
	sregs->u.e.ivor_high[3] =
		vcpu->arch.ivor[BOOKE_IRQPRIO_PERFORMANCE_MONITOR];

	kvmppc_get_sregs_ivor(vcpu, sregs);
}

int kvmppc_core_set_sregs(struct kvm_vcpu *vcpu, struct kvm_sregs *sregs)
{
	struct kvmppc_vcpu_e500 *vcpu_e500 = to_e500(vcpu);

	if (sregs->u.e.impl_id == KVM_SREGS_E_IMPL_FSL) {
		vcpu_e500->svr = sregs->u.e.impl.fsl.svr;
		vcpu_e500->hid0 = sregs->u.e.impl.fsl.hid0;
		vcpu_e500->mcar = sregs->u.e.impl.fsl.mcar;
	}

	if (sregs->u.e.features & KVM_SREGS_E_ARCH206_MMU) {
		vcpu->arch.shared->mas0 = sregs->u.e.mas0;
		vcpu->arch.shared->mas1 = sregs->u.e.mas1;
		vcpu->arch.shared->mas2 = sregs->u.e.mas2;
		vcpu->arch.shared->mas7_3 = sregs->u.e.mas7_3;
		vcpu->arch.shared->mas4 = sregs->u.e.mas4;
		vcpu->arch.shared->mas6 = sregs->u.e.mas6;
	}

	if (!(sregs->u.e.features & KVM_SREGS_E_IVOR))
		return 0;

	if (sregs->u.e.features & KVM_SREGS_E_SPE) {
		vcpu->arch.ivor[BOOKE_IRQPRIO_SPE_UNAVAIL] =
			sregs->u.e.ivor_high[0];
		vcpu->arch.ivor[BOOKE_IRQPRIO_SPE_FP_DATA] =
			sregs->u.e.ivor_high[1];
		vcpu->arch.ivor[BOOKE_IRQPRIO_SPE_FP_ROUND] =
			sregs->u.e.ivor_high[2];
	}

	if (sregs->u.e.features & KVM_SREGS_E_PM) {
		vcpu->arch.ivor[BOOKE_IRQPRIO_PERFORMANCE_MONITOR] =
			sregs->u.e.ivor_high[3];
	}

	return kvmppc_set_sregs_ivor(vcpu, sregs);
}

struct kvm_vcpu *kvmppc_core_vcpu_create(struct kvm *kvm, unsigned int id)
{
	struct kvmppc_vcpu_e500 *vcpu_e500;
	struct kvm_vcpu *vcpu;
	int err;

	vcpu_e500 = kmem_cache_zalloc(kvm_vcpu_cache, GFP_KERNEL);
	if (!vcpu_e500) {
		err = -ENOMEM;
		goto out;
	}

	vcpu = &vcpu_e500->vcpu;
	err = kvm_vcpu_init(vcpu, kvm, id);
	if (err)
		goto free_vcpu;

	err = kvmppc_e500_tlb_init(vcpu_e500);
	if (err)
		goto uninit_vcpu;

	vcpu->arch.shared = (void*)__get_free_page(GFP_KERNEL|__GFP_ZERO);
	if (!vcpu->arch.shared)
		goto uninit_tlb;

	return vcpu;

uninit_tlb:
	kvmppc_e500_tlb_uninit(vcpu_e500);
uninit_vcpu:
	kvm_vcpu_uninit(vcpu);
free_vcpu:
	kmem_cache_free(kvm_vcpu_cache, vcpu_e500);
out:
	return ERR_PTR(err);
}

void kvmppc_core_vcpu_free(struct kvm_vcpu *vcpu)
{
	struct kvmppc_vcpu_e500 *vcpu_e500 = to_e500(vcpu);

	free_page((unsigned long)vcpu->arch.shared);
	kvm_vcpu_uninit(vcpu);
	kvmppc_e500_tlb_uninit(vcpu_e500);
	kmem_cache_free(kvm_vcpu_cache, vcpu_e500);
}

static int __init kvmppc_e500_init(void)
{
	int r, i;
	unsigned long ivor[4];
	unsigned long *handler = kvmppc_booke_handler_addr;
	unsigned long max_ivor = 0;

	r = kvmppc_booke_init();
	if (r)
		return r;

	handler += 16;

	/* copy extra E500 exception handlers */
	ivor[0] = mfspr(SPRN_IVOR32);
	ivor[1] = mfspr(SPRN_IVOR33);
	ivor[2] = mfspr(SPRN_IVOR34);
	ivor[3] = mfspr(SPRN_IVOR35);
	for (i = 0; i < 4; i++) {
		if (ivor[i] > ivor[max_ivor])
			max_ivor = i;

		memcpy((void *)kvmppc_booke_handlers + ivor[i],
		       (void *)handler[i], handler[i + 1] - handler[i]);
	}
	flush_icache_range(kvmppc_booke_handlers,
	                   kvmppc_booke_handlers + ivor[max_ivor] +
	                       handler[max_ivor + 1] - handler[max_ivor]);

	return kvm_init(NULL, sizeof(struct kvmppc_vcpu_e500), 0, THIS_MODULE);
}

static void __exit kvmppc_e500_exit(void)
{
	kvmppc_booke_exit();
}

module_init(kvmppc_e500_init);
module_exit(kvmppc_e500_exit);
