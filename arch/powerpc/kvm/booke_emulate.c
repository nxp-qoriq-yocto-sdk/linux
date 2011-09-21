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
 * Copyright IBM Corp. 2008
 * Copyright 2011 Freescale Semiconductor, Inc.
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 */

#include <linux/kvm_host.h>
#include <asm/disassemble.h>

#include "booke.h"

#define OP_19_XOP_RFI     50
#define OP_19_XOP_RFCI    51
#define OP_19_XOP_RFMCI   38
#define OP_19_XOP_RFDI    39

#define OP_31_XOP_MFMSR   83
#define OP_31_XOP_WRTEE   131
#define OP_31_XOP_MTMSR   146
#define OP_31_XOP_WRTEEI  163

#ifndef CONFIG_KVM_BOOKE_HV
static void kvmppc_emul_rfi(struct kvm_vcpu *vcpu)
{
	vcpu->arch.pc = vcpu->arch.shared->srr0;
	kvmppc_set_msr(vcpu, vcpu->arch.shared->srr1);
}
#endif

static void kvmppc_emul_rfmci(struct kvm_vcpu *vcpu)
{
	vcpu->arch.pc = vcpu->arch.mcsrr0;
	kvmppc_set_msr(vcpu, vcpu->arch.mcsrr1);
}

static void kvmppc_emul_rfdi(struct kvm_vcpu *vcpu)
{
	vcpu->arch.pc = vcpu->arch.dsrr0;
	/* Force MSR_DE when guest does not own debug facilities */
	if (vcpu->guest_debug)
		kvmppc_set_msr(vcpu, vcpu->arch.dsrr1 | MSR_DE);
	else
		kvmppc_set_msr(vcpu, vcpu->arch.dsrr1);
}

static void kvmppc_emul_rfci(struct kvm_vcpu *vcpu)
{
	vcpu->arch.pc = vcpu->arch.csrr0;
	/* Force MSR_DE when guest does not own debug facilities */
	if (vcpu->guest_debug)
		kvmppc_set_msr(vcpu, vcpu->arch.csrr1 | MSR_DE);
	else
		kvmppc_set_msr(vcpu, vcpu->arch.csrr1);
}

int kvmppc_booke_emulate_op(struct kvm_run *run, struct kvm_vcpu *vcpu,
                            unsigned int inst, int *advance)
{
	int emulated = EMULATE_DONE;

	switch (get_op(inst)) {
	case 19:
		switch (get_xop(inst)) {
#ifndef CONFIG_KVM_BOOKE_HV
		case OP_19_XOP_RFI:
			kvmppc_emul_rfi(vcpu);
			kvmppc_set_exit_type(vcpu, EMULATED_RFI_EXITS);
			*advance = 0;
			break;
#endif

		case OP_19_XOP_RFCI:
			kvmppc_emul_rfci(vcpu);
			kvmppc_set_exit_type(vcpu, EMULATED_RFCI_EXITS);
			*advance = 0;
			break;

		case OP_19_XOP_RFMCI:
			kvmppc_emul_rfmci(vcpu);
			kvmppc_set_exit_type(vcpu, EMULATED_RFMCI_EXITS);
			*advance = 0;
			break;

		case OP_19_XOP_RFDI:
			kvmppc_emul_rfdi(vcpu);
			*advance = 0;
			break;

		default:
			emulated = EMULATE_FAIL;
			break;
		}
		break;
#ifndef CONFIG_KVM_BOOKE_HV
	case 31:
		switch (get_xop(inst)) {
			int rt;
			int rs;

		case OP_31_XOP_MFMSR:
			rt = get_rt(inst);
			kvmppc_set_gpr(vcpu, rt, vcpu->arch.shared->msr);
			kvmppc_set_exit_type(vcpu, EMULATED_MFMSR_EXITS);
			break;

		case OP_31_XOP_MTMSR:
			rs = get_rs(inst);
			kvmppc_set_exit_type(vcpu, EMULATED_MTMSR_EXITS);
			kvmppc_set_msr(vcpu, kvmppc_get_gpr(vcpu, rs));
			break;

		case OP_31_XOP_WRTEE:
			rs = get_rs(inst);
			vcpu->arch.shared->msr = (vcpu->arch.shared->msr & ~MSR_EE)
					| (kvmppc_get_gpr(vcpu, rs) & MSR_EE);
			kvmppc_set_exit_type(vcpu, EMULATED_WRTEE_EXITS);
			break;

		case OP_31_XOP_WRTEEI:
			vcpu->arch.shared->msr = (vcpu->arch.shared->msr & ~MSR_EE)
							 | (inst & MSR_EE);
			kvmppc_set_exit_type(vcpu, EMULATED_WRTEE_EXITS);
			break;

		default:
			emulated = EMULATE_FAIL;
		}

		break;

#endif
	default:
		emulated = EMULATE_FAIL;
	}

	return emulated;
}

int kvmppc_booke_emulate_mtspr(struct kvm_vcpu *vcpu, int sprn, int rs)
{
	int emulated = EMULATE_DONE;
	ulong spr_val = kvmppc_get_gpr(vcpu, rs);

	switch (sprn) {
#ifndef CONFIG_KVM_BOOKE_HV
	case SPRN_DEAR:
		vcpu->arch.shared->dar = spr_val; break;
	case SPRN_ESR:
		vcpu->arch.shared->esr = spr_val; break;
	/* Note: SPRG4-7 are user-readable. These values are
	 * loaded into the real SPRGs when resuming the
	 * guest. */
	case SPRN_SPRG4:
		vcpu->arch.sprg4 = spr_val; break;
	case SPRN_SPRG5:
		vcpu->arch.sprg5 = spr_val; break;
	case SPRN_SPRG6:
		vcpu->arch.sprg6 = spr_val; break;
	case SPRN_SPRG7:
		vcpu->arch.sprg7 = spr_val; break;
#endif
	case SPRN_CSRR0:
		vcpu->arch.csrr0 = spr_val; break;
	case SPRN_CSRR1:
		vcpu->arch.csrr1 = spr_val; break;
	case SPRN_MCSRR0:
		vcpu->arch.mcsrr0 = spr_val; break;
	case SPRN_MCSRR1:
		vcpu->arch.mcsrr1 = spr_val; break;
	case SPRN_DSRR0:
		vcpu->arch.dsrr0 = spr_val;
		break;
	case SPRN_DSRR1:
		vcpu->arch.dsrr1 = spr_val;
		break;
	case SPRN_IAC1:
		vcpu->arch.dbg_reg.iac[0] = spr_val;
		kvmppc_recalc_shadow_ac(vcpu);
		break;
	case SPRN_IAC2:
		vcpu->arch.dbg_reg.iac[1] = spr_val;
		kvmppc_recalc_shadow_ac(vcpu);
		break;
#ifndef CONFIG_FSL_BOOKE
	case SPRN_IAC3:
		vcpu->arch.dbg_reg.iac[2] = spr_val;
		kvmppc_recalc_shadow_ac(vcpu);
		break;
	case SPRN_IAC4:
		vcpu->arch.dbg_reg.iac[3] = spr_val;
		kvmppc_recalc_shadow_ac(vcpu);
		break;
#endif
	case SPRN_DAC1:
		vcpu->arch.dbg_reg.dac[0] = spr_val;
		kvmppc_recalc_shadow_ac(vcpu);
		break;
	case SPRN_DAC2:
		vcpu->arch.dbg_reg.dac[1] = spr_val;
		kvmppc_recalc_shadow_ac(vcpu);
		break;
	case SPRN_DBCR0:
		spr_val &= (DBCR0_IDM | DBCR0_IC | DBCR0_BT | DBCR0_TIE |
			DBCR0_IAC1 | DBCR0_IAC2 | DBCR0_IAC3 | DBCR0_IAC4  |
			DBCR0_DAC1R | DBCR0_DAC1W | DBCR0_DAC2R | DBCR0_DAC2W);

		vcpu->arch.dbg_reg.dbcr0 = spr_val;
		kvmppc_recalc_shadow_dbcr(vcpu);
		break;
	case SPRN_DBCR1:
		vcpu->arch.dbg_reg.dbcr1 = spr_val;
		kvmppc_recalc_shadow_dbcr(vcpu);
		break;
	case SPRN_DBCR2:
		vcpu->arch.dbg_reg.dbcr2 = spr_val;
		kvmppc_recalc_shadow_dbcr(vcpu);
		break;
#ifdef CONFIG_KVM_E500MC
	case SPRN_DBCR4:
		vcpu->arch.dbg_reg.dbcr4 = spr_val;
		vcpu->arch.shadow_dbg_reg.dbcr4 = spr_val;
		break;
#endif
	case SPRN_DBSR:
		kvmppc_clr_dbsr_bits(vcpu, spr_val);
		break;
	case SPRN_TSR:
		kvmppc_clr_tsr_bits(vcpu, spr_val);
		break;
	case SPRN_TCR:
		/* WRC can only be programmed when WRC=0 */
		if (TCR_WRC_MASK & vcpu->arch.tcr)
			spr_val &= ~TCR_WRC_MASK;
		kvmppc_set_tcr(vcpu,
		               spr_val | (TCR_WRC_MASK & vcpu->arch.tcr));
		break;
	case SPRN_IVPR:
		vcpu->arch.ivpr = spr_val;
#ifdef CONFIG_KVM_BOOKE_HV
		mtspr(SPRN_GIVPR, spr_val);
#endif
		break;
	case SPRN_IVOR0:
		vcpu->arch.ivor[BOOKE_IRQPRIO_CRITICAL] = spr_val;
		break;
	case SPRN_IVOR1:
		vcpu->arch.ivor[BOOKE_IRQPRIO_MACHINE_CHECK] = spr_val;
		break;
	case SPRN_IVOR2:
		vcpu->arch.ivor[BOOKE_IRQPRIO_DATA_STORAGE] = spr_val;
#ifdef CONFIG_KVM_BOOKE_HV
		mtspr(SPRN_GIVOR2, spr_val);
#endif
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
#ifdef CONFIG_KVM_BOOKE_HV
		mtspr(SPRN_GIVOR8, spr_val);
#endif
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

int kvmppc_booke_emulate_mfspr(struct kvm_vcpu *vcpu, int sprn, int rt)
{
	int emulated = EMULATE_DONE;

	switch (sprn) {
#ifndef CONFIG_KVM_BOOKE_HV
	case SPRN_IVPR:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.ivpr); break;
	case SPRN_DEAR:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.shared->dar); break;
	case SPRN_ESR:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.shared->esr); break;
#endif
	case SPRN_CSRR0:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.csrr0); break;
	case SPRN_CSRR1:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.csrr1); break;
	case SPRN_MCSRR0:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.mcsrr0); break;
	case SPRN_MCSRR1:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.mcsrr1); break;
	case SPRN_DSRR0:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.dsrr0);
		break;
	case SPRN_DSRR1:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.dsrr1);
		break;
	case SPRN_IAC1:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.dbg_reg.iac[0]);
		break;
	case SPRN_IAC2:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.dbg_reg.iac[1]);
		break;
#ifndef CONFIG_FSL_BOOKE
	case SPRN_IAC3:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.dbg_reg.iac[2]);
		break;
	case SPRN_IAC4:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.dbg_reg.iac[3]);
		break;
#endif
	case SPRN_DAC1:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.dbg_reg.dac[0]);
		break;
	case SPRN_DAC2:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.dbg_reg.dac[1]);
		break;
	case SPRN_DBCR0:
		/*
		 * If debug resources are taken by host (say QEMU) then
		 * debug resources are not available to guest. For Guest
		 * it is like external debugger have taken the resources.
		 */
		if (vcpu->guest_debug)
			kvmppc_set_gpr(vcpu, rt, vcpu->arch.dbg_reg.dbcr0
								| DBCR0_EDM);
		else
			kvmppc_set_gpr(vcpu, rt, vcpu->arch.dbg_reg.dbcr0);
		break;
	case SPRN_DBCR1:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.dbg_reg.dbcr1); break;
	case SPRN_DBCR2:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.dbg_reg.dbcr2); break;
#ifdef CONFIG_KVM_E500MC
	case SPRN_DBCR4:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.dbg_reg.dbcr4);
		break;
#endif
	case SPRN_DBSR:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.dbsr); break;
	case SPRN_TSR:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.tsr); break;
	case SPRN_TCR:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.tcr); break;

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
