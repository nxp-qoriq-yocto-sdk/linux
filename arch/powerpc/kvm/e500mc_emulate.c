/*
 * Copyright (C) 2010 Freescale Semiconductor, Inc. All rights reserved.
 *
 * Author: Varun Sethi, <varun.sethi@freescale.com>
 *
 * Description:
 * This file is derived from arch/powerpc/kvm/e500_emulate.c,
 * by Yu Liu <yu.liu@freescale.com>.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2, as
 * published by the Free Software Foundation.
 */

#include <asm/kvm_ppc.h>
#include <asm/disassemble.h>
#include <asm/kvm_e500mc.h>

#include "booke.h"
#include "e500mc_tlb.h"

#define XOP_TLBIVAX 786
#define XOP_TLBSX   914
#define XOP_TLBRE   946
#define XOP_TLBWE   978
#define XOP_TLBILX  18

int kvmppc_core_emulate_op(struct kvm_run *run, struct kvm_vcpu *vcpu,
                           unsigned int inst, int *advance)
{
	int emulated = EMULATE_DONE;
	int ra;
	int rb;
	int rt;

	switch (get_op(inst)) {
	case 31:
		switch (get_xop(inst)) {

		case XOP_TLBRE:
			emulated = kvmppc_e500mc_emul_tlbre(vcpu);
			break;

		case XOP_TLBWE:
			emulated = kvmppc_e500mc_emul_tlbwe(vcpu);
			break;

		case XOP_TLBSX:
			rb = get_rb(inst);
			emulated = kvmppc_e500mc_emul_tlbsx(vcpu,rb);
			break;

		case XOP_TLBILX:
			ra = get_ra(inst);
			rb = get_rb(inst);
			rt = get_rt(inst);
			emulated = kvmppc_e500mc_emul_tlbilx(vcpu, rt, ra, rb);
			break;

		case XOP_TLBIVAX:
			ra = get_ra(inst);
			rb = get_rb(inst);
			emulated = kvmppc_e500mc_emul_tlbivax(vcpu, ra, rb);
			break;

		default:
			emulated = EMULATE_FAIL;
		}

		break;

	default:
		emulated = EMULATE_FAIL;
	}

	if (emulated == EMULATE_FAIL)
		emulated = kvmppc_bookehv_emulate_op(run, vcpu, inst, advance);

	return emulated;
}

int kvmppc_core_emulate_mtspr(struct kvm_vcpu *vcpu, int sprn, int rs)
{
	struct kvmppc_vcpu_e500mc *vcpu_e500mc = to_e500mc(vcpu);
	int emulated = EMULATE_DONE;
	ulong spr_val = kvmppc_get_gpr(vcpu, rs);

	switch (sprn) {
	case SPRN_L1CSR0:
		vcpu_e500mc->l1csr0 = spr_val;
		vcpu_e500mc->l1csr0 &= ~(L1CSR0_DCFI | L1CSR0_CLFC);
		break;
	case SPRN_L1CSR1:
		vcpu_e500mc->l1csr1 = spr_val; break;
	case SPRN_HID0:
		vcpu_e500mc->hid0 = spr_val; break;
	case SPRN_HID1:
		vcpu_e500mc->hid1 = spr_val; break;

	case SPRN_MMUCSR0:
		emulated = kvmppc_e500mc_emul_mt_mmucsr0(vcpu_e500mc,
				spr_val);
		break;

	/* extra exceptions */
	case SPRN_IVOR32:
		vcpu->arch.ivor[BOOKE_IRQPRIO_SPE_UNAVAIL] = spr_val;
		break;
	case SPRN_IVOR33:
		vcpu->arch.ivor[BOOKE_IRQPRIO_SPE_FP_DATA] = spr_val;
		break;
	case SPRN_IVOR34:
		vcpu->arch.ivor[BOOKE_IRQPRIO_SPE_FP_ROUND] = spr_val;
		break;
	case SPRN_IVOR35:
		vcpu->arch.ivor[BOOKE_IRQPRIO_PERFORMANCE_MONITOR] = spr_val;
		break;
	case SPRN_IVOR36:
		vcpu->arch.ivor[BOOKE_IRQPRIO_DBELL] = spr_val;
		break;
	case SPRN_IVOR37:
		vcpu->arch.ivor[BOOKE_IRQPRIO_DBELL_CRIT] = spr_val;
		break;

	default:
		emulated = kvmppc_bookehv_emulate_mtspr(vcpu, sprn, rs);
	}

	return emulated;
}

int kvmppc_core_emulate_mfspr(struct kvm_vcpu *vcpu, int sprn, int rt)
{
	struct kvmppc_vcpu_e500mc *vcpu_e500mc = to_e500mc(vcpu);
	int emulated = EMULATE_DONE;

	switch (sprn) {
	case SPRN_TLB0CFG:
		kvmppc_set_gpr(vcpu, rt, vcpu_e500mc->tlb0cfg); break;
	case SPRN_TLB1CFG:
		kvmppc_set_gpr(vcpu, rt, vcpu_e500mc->tlb1cfg); break;
	case SPRN_L1CSR0:
		kvmppc_set_gpr(vcpu, rt, vcpu_e500mc->l1csr0); break;
	case SPRN_L1CSR1:
		kvmppc_set_gpr(vcpu, rt, vcpu_e500mc->l1csr1); break;
	case SPRN_HID0:
		kvmppc_set_gpr(vcpu, rt, vcpu_e500mc->hid0); break;
	case SPRN_HID1:
		kvmppc_set_gpr(vcpu, rt, vcpu_e500mc->hid1); break;
	case SPRN_SVR:
		kvmppc_set_gpr(vcpu, rt, vcpu_e500mc->svr); break;

	case SPRN_MMUCSR0:
		kvmppc_set_gpr(vcpu, rt, 0); break;

	case SPRN_MMUCFG:
		kvmppc_set_gpr(vcpu, rt, kvmppc_get_mmucfg(vcpu)); break;

	/* extra exceptions */
	case SPRN_IVOR32:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.ivor[BOOKE_IRQPRIO_SPE_UNAVAIL]);
		break;
	case SPRN_IVOR33:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.ivor[BOOKE_IRQPRIO_SPE_FP_DATA]);
		break;
	case SPRN_IVOR34:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.ivor[BOOKE_IRQPRIO_SPE_FP_ROUND]);
		break;
	case SPRN_IVOR35:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.ivor[BOOKE_IRQPRIO_PERFORMANCE_MONITOR]);
		break;
	case SPRN_IVOR36:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.ivor[BOOKE_IRQPRIO_DBELL]);
		break;
	case SPRN_IVOR37:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.ivor[BOOKE_IRQPRIO_DBELL_CRIT]);
		break;
	default:
		emulated = kvmppc_bookehv_emulate_mfspr(vcpu, sprn, rt);
	}

	return emulated;
}
