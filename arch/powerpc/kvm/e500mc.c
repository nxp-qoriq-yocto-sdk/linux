/*
 * Copyright (C) 2010 Freescale Semiconductor, Inc. All rights reserved.
 *
 * Author: Varun Sethi, <varun.sethi@freescale.com>
 *
 * Description:
 * This file is derived from arch/powerpc/kvm/e500.c,
 * by Yu Liu <yu.liu@freescale.com>.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2, as
 * published by the Free Software Foundation.
 */

#include <linux/kvm_host.h>
#include <linux/kvm_host.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/idr.h>

#include <asm/reg.h>
#include <asm/cputable.h>
#include <asm/tlbflush.h>
#include <asm/kvm_ppc.h>
#include <asm/doorbell.h>

#include "booke.h"
#include "e500.h"

static DEFINE_SPINLOCK(lpid_idr_lock);
static struct idr lpid_id_ns;

int alloc_lpid(struct kvm_vcpu *vcpu)
{
	int err, lpid;

retry:
	if (unlikely(!idr_pre_get(&lpid_id_ns, GFP_KERNEL)))
		return -ENOSPC;

	spin_lock(&lpid_idr_lock);
	/* Allocate guest lpid's >= 1 */
	err = idr_get_new_above(&lpid_id_ns, vcpu, 1, &lpid);
	spin_unlock(&lpid_idr_lock);

	if (err) {
		if (err == -EAGAIN)
			goto retry;
		/* IDR is probably full, retry may work if a guest is free'd */
		return err;
	}

	vcpu->arch.lpid = lpid;
	return 0;
}

void kvmppc_set_pending_interrupt(struct kvm_vcpu *vcpu, enum int_class type)
{
	unsigned long msg_type;
	unsigned long msg;

	switch (type) {
	case INT_CLASS_NONCRIT:
		msg_type = MSG_GBELL;
		break;
	case INT_CLASS_CRIT:
		msg_type = MSG_GBELL_CRIT;
		break;
	case INT_CLASS_MC:
		msg_type = MSG_GBELL_MCHK;
		break;
	default:
		return;
	}

	msg = msg_type | (vcpu->arch.lpid << 14) | vcpu->arch.gpir;
	send_doorbell_msg(msg);
}


void kvmppc_core_load_host_debugstate(struct kvm_vcpu *vcpu)
{
}

void kvmppc_core_load_guest_debugstate(struct kvm_vcpu *vcpu)
{
}

void kvmppc_core_vcpu_load(struct kvm_vcpu *vcpu, int cpu)
{
	struct kvmppc_vcpu_e500 *vcpu_e500 = to_e500(vcpu);

	local_irq_disable();
       current->thread.kvm_shadow_vcpu = vcpu;

       /* Retore the PM Registers on VCPU load */
       if (vcpu->arch.pm_is_reserved)
		kvmppc_load_perfmon_regs(vcpu);

	mtspr(SPRN_LPID, vcpu->arch.lpid);
	mtspr(SPRN_EPCR, vcpu->arch.epcr);
	mtspr(SPRN_GPIR, vcpu->arch.gpir);
	mtspr(SPRN_MSRP, vcpu->arch.msrp);

	mtspr(SPRN_GIVPR, vcpu->arch.ivpr);
	mtspr(SPRN_GIVOR2, vcpu->arch.ivor[BOOKE_IRQPRIO_DATA_STORAGE]);
	mtspr(SPRN_GIVOR8, vcpu->arch.ivor[BOOKE_IRQPRIO_SYSCALL]);
	mtspr(SPRN_GSPRG0, (unsigned long)vcpu->arch.shared->sprg0);
	mtspr(SPRN_GSPRG1, (unsigned long)vcpu->arch.shared->sprg1);
	mtspr(SPRN_GSPRG2, (unsigned long)vcpu->arch.shared->sprg2);
	mtspr(SPRN_GSPRG3, (unsigned long)vcpu->arch.shared->sprg3);

	mtspr(SPRN_GSRR0, vcpu->arch.shared->srr0);
	mtspr(SPRN_GSRR1, vcpu->arch.shared->srr1);

	mtspr(SPRN_GEPR, vcpu->arch.shared->epr);
	mtspr(SPRN_GDEAR, vcpu->arch.shared->dar);
	mtspr(SPRN_GESR, vcpu->arch.shared->esr);

	if (vcpu->arch.oldpir != mfspr(SPRN_PIR))
		kvmppc_core_tlbil_all(vcpu_e500);

	local_irq_enable();

	kvmppc_load_guest_fp(vcpu);
}

void kvmppc_core_vcpu_put(struct kvm_vcpu *vcpu)
{
	vcpu->arch.shared->sprg0 = mfspr(SPRN_GSPRG0);
	vcpu->arch.shared->sprg1 = mfspr(SPRN_GSPRG1);
	vcpu->arch.shared->sprg2 = mfspr(SPRN_GSPRG2);
	vcpu->arch.shared->sprg3 = mfspr(SPRN_GSPRG3);
	vcpu->arch.msrp = mfspr(SPRN_MSRP);

	vcpu->arch.shared->srr0 = mfspr(SPRN_GSRR0);
	vcpu->arch.shared->srr1 = mfspr(SPRN_GSRR1);

	vcpu->arch.shared->epr = mfspr(SPRN_GEPR);
	vcpu->arch.shared->dar = mfspr(SPRN_GDEAR);
	vcpu->arch.shared->esr = mfspr(SPRN_GESR);

	vcpu->arch.oldpir = mfspr(SPRN_PIR);

       if (vcpu->arch.pm_is_reserved)
		kvmppc_save_perfmon_regs(vcpu);

       current->thread.kvm_shadow_vcpu = NULL;
}

int kvmppc_core_check_processor_compat(void)
{
	int r;

	if (strcmp(cur_cpu_spec->cpu_name, "e500mc") == 0)
		r = 0;
	else
		r = -ENOTSUPP;

	return r;
}

int kvmppc_core_vcpu_setup(struct kvm_vcpu *vcpu)
{
	struct kvmppc_vcpu_e500 *vcpu_e500 = to_e500(vcpu);
	int err;

	err = alloc_lpid(vcpu);
	if (err)
		return err;

	vcpu->arch.epcr = EPCR_DSIGS | EPCR_DGTMI | EPCR_DUVD;
	vcpu->arch.gpir = 0;

	if (vcpu->arch.pm_is_reserved)
		vcpu->arch.msrp = MSRP_UCLEP | MSRP_DEP;
	else
		vcpu->arch.msrp = MSRP_UCLEP | MSRP_DEP | MSRP_PMMP;

	/* Registers init */
	vcpu->arch.pvr = mfspr(SPRN_PVR);
	vcpu_e500->svr = mfspr(SPRN_SVR);

	/* Since booke kvm only support one core, update all vcpus' PIR to 0 */
	vcpu->vcpu_id = 0;

	return 0;
}

/* 'linear_address' is actually an encoding of AS|PID|EADDR . */
int kvmppc_core_vcpu_translate(struct kvm_vcpu *vcpu,
                               struct kvm_translation *tr)
{
	return 0;
}

void kvmppc_core_get_sregs(struct kvm_vcpu *vcpu, struct kvm_sregs *sregs)
{
	struct kvmppc_vcpu_e500 *vcpu_e500 = to_e500(vcpu);

	sregs->u.e.features |= KVM_SREGS_E_ARCH206_MMU | KVM_SREGS_E_PM |
	                       KVM_SREGS_E_PC;
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
	sregs->u.e.tlbcfg[0] = vcpu->arch.tlbcfg[0];
	sregs->u.e.tlbcfg[1] = vcpu->arch.tlbcfg[1];
	sregs->u.e.tlbcfg[2] = 0;
	sregs->u.e.tlbcfg[3] = 0;

	sregs->u.e.ivor_high[3] =
		vcpu->arch.ivor[BOOKE_IRQPRIO_PERFORMANCE_MONITOR];
	sregs->u.e.ivor_high[4] = vcpu->arch.ivor[BOOKE_IRQPRIO_DBELL];
	sregs->u.e.ivor_high[5] = vcpu->arch.ivor[BOOKE_IRQPRIO_DBELL_CRIT];

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

	if (sregs->u.e.features & KVM_SREGS_E_PM) {
		vcpu->arch.ivor[BOOKE_IRQPRIO_PERFORMANCE_MONITOR] =
			sregs->u.e.ivor_high[3];
	}

	if (sregs->u.e.features & KVM_SREGS_E_PC) {
		vcpu->arch.ivor[BOOKE_IRQPRIO_DBELL] =
			sregs->u.e.ivor_high[4];
		vcpu->arch.ivor[BOOKE_IRQPRIO_DBELL_CRIT] =
			sregs->u.e.ivor_high[5];
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

	/* Invalid PIR value -- this LPID dosn't have valid state on any cpu */
	vcpu->arch.oldpir = 0xffffffff;

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
	kvmppc_e500_tlb_uninit(vcpu_e500);
	kvm_vcpu_uninit(vcpu);
	kmem_cache_free(kvm_vcpu_cache, vcpu_e500);

	spin_lock(&lpid_idr_lock);
	idr_remove(&lpid_id_ns, vcpu->arch.lpid);
	spin_unlock(&lpid_idr_lock);
}

static int __init kvmppc_e500mc_init(void)
{
	int r;

	r = kvmppc_bookehv_init();
	if (r)
		return r;

	idr_init(&lpid_id_ns);

	return kvm_init(NULL, sizeof(struct kvmppc_vcpu_e500), 0, THIS_MODULE);
}

static void __exit kvmppc_e500mc_exit(void)
{
	kvmppc_bookehv_exit();
}

module_init(kvmppc_e500mc_init);
module_exit(kvmppc_e500mc_exit);
