/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright (C) 2010 Freescale Semiconductor, Inc. All rights reserved.
 *
 * Author: Varun Sethi <varun.sethi@freescale.com>
 *
 * Description:
 * This file is derived from arch/powerpc/kvm/booke_emulate.c
 * by Hollis Blanchard <hollisb@us.ibm.com>
 *
 */

#include <linux/kvm_host.h>
#include <asm/disassemble.h>

#include "booke.h"

int kvmppc_bookehv_emulate_op(struct kvm_run *run, struct kvm_vcpu *vcpu,
                            unsigned int inst, int *advance)
{
	int emulated = EMULATE_FAIL;

	return emulated;
}

int kvmppc_bookehv_emulate_mtspr(struct kvm_vcpu *vcpu, int sprn, int rs)
{
	int emulated = EMULATE_DONE;
	ulong spr_val = kvmppc_get_gpr(vcpu, rs);

	switch (sprn) {
	case SPRN_DBCR0:
		vcpu->arch.dbcr0 = spr_val; break;
	case SPRN_DBCR1:
		vcpu->arch.dbcr1 = spr_val; break;
	case SPRN_DBSR:
		vcpu->arch.dbsr &= ~spr_val; break;
	case SPRN_TSR:
		vcpu->arch.tsr &= ~spr_val; break;
	case SPRN_TCR:
		vcpu->arch.tcr = spr_val;
		kvmppc_emulate_dec(vcpu);
		break;
	case SPRN_IVPR:
		vcpu->arch.ivpr = spr_val;
		mtspr(SPRN_GIVPR, spr_val);
		break;
	case SPRN_IVOR0:
		vcpu->arch.ivor[BOOKE_IRQPRIO_CRITICAL] = spr_val;
		break;
	case SPRN_IVOR1:
		vcpu->arch.ivor[BOOKE_IRQPRIO_MACHINE_CHECK] = spr_val;
		break;
	case SPRN_IVOR2:
		vcpu->arch.ivor[BOOKE_IRQPRIO_DATA_STORAGE] = spr_val;
		mtspr(SPRN_GIVOR2, spr_val);
		break;
	case SPRN_IVOR3:
		vcpu->arch.ivor[BOOKE_IRQPRIO_INST_STORAGE] = spr_val;
		break;
	case SPRN_IVOR4:
		vcpu->arch.ivor[BOOKE_IRQPRIO_EXTERNAL] = spr_val;
		break;
	case SPRN_IVOR5:
		vcpu->arch.ivor[BOOKE_IRQPRIO_ALIGNMENT] = spr_val;
		break;
	case SPRN_IVOR6:
		vcpu->arch.ivor[BOOKE_IRQPRIO_PROGRAM] = spr_val;
		break;
	case SPRN_IVOR7:
		vcpu->arch.ivor[BOOKE_IRQPRIO_FP_UNAVAIL] = spr_val;
		break;
	case SPRN_IVOR8:
		vcpu->arch.ivor[BOOKE_IRQPRIO_SYSCALL] = spr_val;
		mtspr(SPRN_GIVOR8, spr_val);
		break;
	case SPRN_IVOR9:
		vcpu->arch.ivor[BOOKE_IRQPRIO_AP_UNAVAIL] = spr_val;
		break;
	case SPRN_IVOR10:
		vcpu->arch.ivor[BOOKE_IRQPRIO_DECREMENTER] = spr_val;
		break;
	case SPRN_IVOR11:
		vcpu->arch.ivor[BOOKE_IRQPRIO_FIT] = spr_val;
		break;
	case SPRN_IVOR12:
		vcpu->arch.ivor[BOOKE_IRQPRIO_WATCHDOG] = spr_val;
		break;
	case SPRN_IVOR13:
		vcpu->arch.ivor[BOOKE_IRQPRIO_DTLB_MISS] = spr_val;
		break;
	case SPRN_IVOR14:
		vcpu->arch.ivor[BOOKE_IRQPRIO_ITLB_MISS] = spr_val;
		break;
	case SPRN_IVOR15:
		vcpu->arch.ivor[BOOKE_IRQPRIO_DEBUG] = spr_val;
		break;

	default:
		emulated = EMULATE_FAIL;
	}

	return emulated;
}

int kvmppc_bookehv_emulate_mfspr(struct kvm_vcpu *vcpu, int sprn, int rt)
{
	int emulated = EMULATE_DONE;

	switch (sprn) {
	case SPRN_IVPR:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.ivpr); break;
	case SPRN_DBCR0:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.dbcr0); break;
	case SPRN_DBCR1:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.dbcr1); break;
	case SPRN_DBSR:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.dbsr); break;

	case SPRN_IVOR0:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.ivor[BOOKE_IRQPRIO_CRITICAL]);
		break;
	case SPRN_IVOR1:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.ivor[BOOKE_IRQPRIO_MACHINE_CHECK]);
		break;
	case SPRN_IVOR2:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.ivor[BOOKE_IRQPRIO_DATA_STORAGE]);
		break;
	case SPRN_IVOR3:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.ivor[BOOKE_IRQPRIO_INST_STORAGE]);
		break;
	case SPRN_IVOR4:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.ivor[BOOKE_IRQPRIO_EXTERNAL]);
		break;
	case SPRN_IVOR5:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.ivor[BOOKE_IRQPRIO_ALIGNMENT]);
		break;
	case SPRN_IVOR6:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.ivor[BOOKE_IRQPRIO_PROGRAM]);
		break;
	case SPRN_IVOR7:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.ivor[BOOKE_IRQPRIO_FP_UNAVAIL]);
		break;
	case SPRN_IVOR8:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.ivor[BOOKE_IRQPRIO_SYSCALL]);
		break;
	case SPRN_IVOR9:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.ivor[BOOKE_IRQPRIO_AP_UNAVAIL]);
		break;
	case SPRN_IVOR10:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.ivor[BOOKE_IRQPRIO_DECREMENTER]);
		break;
	case SPRN_IVOR11:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.ivor[BOOKE_IRQPRIO_FIT]);
		break;
	case SPRN_IVOR12:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.ivor[BOOKE_IRQPRIO_WATCHDOG]);
		break;
	case SPRN_IVOR13:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.ivor[BOOKE_IRQPRIO_DTLB_MISS]);
		break;
	case SPRN_IVOR14:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.ivor[BOOKE_IRQPRIO_ITLB_MISS]);
		break;
	case SPRN_IVOR15:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.ivor[BOOKE_IRQPRIO_DEBUG]);
		break;

	default:
		emulated = EMULATE_FAIL;
	}

	return emulated;
}
