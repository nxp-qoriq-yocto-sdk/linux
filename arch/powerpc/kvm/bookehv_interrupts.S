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
 * This file is derived from arch/powerpc/kvm/booke_interrupts.s
 * by Hollis Blanchard <hollisb@us.ibm.com>
 *
 */

#include <asm/ppc_asm.h>
#include <asm/kvm_asm.h>
#include <asm/reg.h>
#include <asm/mmu-44x.h>
#include <asm/page.h>
#include <asm/asm-compat.h>
#include <asm/asm-offsets.h>

#define GET_SHADOW_VCPU(regd, regs)    \
	lwz	regd, THREAD_KVM_SVCPU(regs)

#define SET_SHADOW_VCPU(reg)    \
        stw     reg, (THREAD + THREAD_KVM_SVCPU)(r2)

#define KVMPPC_MSR_MASK (MSR_GS)

#define VCPU_GPR(n)     (VCPU_GPRS + (n * 4))
#define VCPU_GUEST_SPRG(n)     (VCPU_GUEST_SPRGS + (n * 4))

/* The host stack layout: */
#define HOST_R1         0 /* Implied by stwu. */
#define HOST_CALLEE_LR  4
#define HOST_RUN        8
/* r2 is special: it holds 'current', and it made nonvolatile in the
 * kernel with the -ffixed-r2 gcc option. */
#define HOST_R2         12
#define HOST_NV_GPRS    16
#define HOST_NV_GPR(n)  (HOST_NV_GPRS + ((n - 14) * 4))
#define HOST_MIN_STACK_SIZE (HOST_NV_GPR(31) + 4)
#define HOST_STACK_SIZE (((HOST_MIN_STACK_SIZE + 15) / 16) * 16) /* Align. */
#define HOST_STACK_LR   (HOST_STACK_SIZE + 4) /* In caller stack frame. */

#define NEED_INST_MASK_LOW ((1<<BOOKE_INTERRUPT_DTLB_MISS) | \
			    (1<<BOOKE_INTERRUPT_DATA_STORAGE))

#define NEED_INST_MASK_HIGH (1<<(BOOKE_HV_PRIV - 32))

#define NEED_DEAR_MASK ((1<<BOOKE_INTERRUPT_DATA_STORAGE) | \
                        (1<<BOOKE_INTERRUPT_DTLB_MISS))

#define NEED_ESR_MASK ((1<<BOOKE_INTERRUPT_INST_STORAGE) | \
                       (1<<BOOKE_INTERRUPT_PROGRAM) | \
                       (1<<BOOKE_INTERRUPT_DTLB_MISS) | \
                       (1<<BOOKE_INTERRUPT_ALIGNMENT))

#define NEED_HOST_HANDLER_MASK_LOW ((1<<BOOKE_INTERRUPT_EXTERNAL) | \
                                    (1<<BOOKE_INTERRUPT_DECREMENTER))

#define NEED_HOST_HANDLER_MASK_HIGH (1<<(BOOKE_INTERRUPT_DOORBELL - 32))

#define NEED_GS_REG_SAVE_MASK (1<<(BOOKE_HV_GUEST_DBELL - 32))

#define NEED_CRIT_SAVE_REGS_HIGH (1<<(BOOKE_INTERRUPT_HV_GS_DBELL_CRIT - 32))

#define NEED_DBG_SAVE_REGS (1<<BOOKE_INTERRUPT_DEBUG)

#define NEED_MCHK_SAVE_REGS (1<<BOOKE_INTERRUPT_MACHINE_CHECK)

#define DBCR0_AC_BITS	(DBCR0_IAC1 | DBCR0_IAC2 | DBCR0_IAC3 | DBCR0_IAC4 | \
			 DBCR0_DAC1R | DBCR0_DAC1W | DBCR0_DAC2R | DBCR0_DAC2W)

/* Registers:
 *  r10: THREAD_POINTER
 *  r13: guest cr
 *  SPRG_SCRATCH0: guest r10
 *  THREAD_NORMSAVE(0): guest r11
 *  THREAD_NORMSAVE(2): guest r13
 */
.macro KVM_HANDLER ivor_nr
_GLOBAL(kvmppc_handler_\ivor_nr)
	mr	r11, r4
	/* Get pointer to vcpu and record exit number. */
	GET_SHADOW_VCPU(r4, r10)
	PPC_STL r11, VCPU_GPR(r4)(r4)
	stw	r13, VCPU_CR(r4)
	PPC_STL	r5, VCPU_GPR(r5)(r4)
	mfspr	r5, SPRN_SPRG_RSCRATCH0
	PPC_STL	r6, VCPU_GPR(r6)(r4)
	PPC_STL	r8, VCPU_GPR(r8)(r4)
	PPC_STL	r9, VCPU_GPR(r9)(r4)
	PPC_STL r5, VCPU_GPR(r10)(r4)
	PPC_LL	r5, THREAD_NORMSAVE(0)(r10)
	PPC_STL r5, VCPU_GPR(r11)(r4)
	PPC_LL	r5, THREAD_NORMSAVE(2)(r10)
	PPC_STL r5, VCPU_GPR(r13)(r4)
	mfctr	r5
	PPC_STL	r5, VCPU_CTR(r4)
	li	r5, \ivor_nr
	b	kvmppc_resume_host
.endm

/* Registers:
 *  r10: THREAD_POINTER
 *  r9, r10, r11, cr: exception
 *  stack
 *  r9: cr
 *  r8: exceptionstack pointer
 *  SPRG_SCRATCH_\lvl: r8
 */
.macro KVM_LVL_HANDLER ivor_nr scratch
_GLOBAL(kvmppc_handler_\ivor_nr)
	mr	r11, r4
	/* Get pointer to vcpu and record exit number. */
	GET_SHADOW_VCPU(r4, r10)
	PPC_STL r11, VCPU_GPR(r4)(r4)
	stw	r9, VCPU_CR(r4)
	PPC_STL	r5, VCPU_GPR(r5)(r4)
	PPC_STL	r6, VCPU_GPR(r6)(r4)
	PPC_LL	r5, GPR10(r8)
	PPC_STL	r5, VCPU_GPR(r10)(r4)
	PPC_STL	r13, VCPU_GPR(r13)(r4)
	PPC_LL	r5, GPR9(r8)
	PPC_STL r5, VCPU_GPR(r9)(r4)
	PPC_LL	r5, GPR11(r8)
	PPC_STL r5, VCPU_GPR(r11)(r4)
	mfspr	r5, \scratch
	PPC_STL r5, VCPU_GPR(r8)(r4)
	mfctr	r5
	PPC_STL	r5, VCPU_CTR(r4)
	li	r5, \ivor_nr
	b	kvmppc_resume_host
.endm

KVM_HANDLER BOOKE_INTERRUPT_INST_STORAGE
KVM_HANDLER BOOKE_INTERRUPT_DATA_STORAGE
KVM_HANDLER BOOKE_INTERRUPT_ALIGNMENT
KVM_HANDLER BOOKE_INTERRUPT_PROGRAM
KVM_HANDLER BOOKE_INTERRUPT_EXTERNAL
KVM_HANDLER BOOKE_INTERRUPT_DECREMENTER
KVM_HANDLER BOOKE_INTERRUPT_FP_UNAVAIL
KVM_HANDLER BOOKE_INTERRUPT_AP_UNAVAIL
KVM_HANDLER BOOKE_INTERRUPT_DTLB_MISS
KVM_HANDLER BOOKE_INTERRUPT_ITLB_MISS
KVM_HANDLER BOOKE_INTERRUPT_SPE_UNAVAIL
KVM_HANDLER BOOKE_INTERRUPT_SPE_FP_DATA
KVM_HANDLER BOOKE_INTERRUPT_SPE_FP_ROUND
KVM_HANDLER BOOKE_HV_PRIV
KVM_HANDLER BOOKE_HV_SYSCALL
KVM_HANDLER BOOKE_HV_GUEST_DBELL
KVM_HANDLER BOOKE_INTERRUPT_DOORBELL
KVM_LVL_HANDLER BOOKE_INTERRUPT_HV_GS_DBELL_CRIT SPRN_SPRG_RSCRATCH_CRIT
KVM_LVL_HANDLER BOOKE_INTERRUPT_DEBUG SPRN_SPRG_RSCRATCH_DBG
KVM_LVL_HANDLER BOOKE_INTERRUPT_MACHINE_CHECK SPRN_SPRG_RSCRATCH_MC
KVM_HANDLER BOOKE_INTERRUPT_PERFORMANCE_MONITOR


/* Registers:
 *  SPRG_SCRATCH0: guest r10
 *  r4: vcpu pointer
 *  r5: KVM exit number
 */
_GLOBAL(kvmppc_resume_host)
	PPC_STL	r3, VCPU_GPR(r3)(r4)
	PPC_STL	r7, VCPU_GPR(r7)(r4)

	mfspr	r3, SPRN_PID
	stw	r3, VCPU_GUEST_PID(r4)
	/* Restore Host PID here */
	lwz	r3, VCPU_HOST_PID(r4)
	mtspr	SPRN_PID, r3

	mfspr	r6, SPRN_VRSAVE
	mfspr	r3, SPRN_SPRG4R
	mfspr	r7, SPRN_SPRG5R
	mfspr	r8, SPRN_SPRG6R
	mfspr	r9, SPRN_SPRG7R
	PPC_STL	r6, VCPU_VRSAVE(r4)
	PPC_STL	r3, VCPU_SPRG4(r4)
	PPC_STL	r7, VCPU_SPRG5(r4)
	PPC_STL	r8, VCPU_SPRG6(r4)
	PPC_STL	r9, VCPU_SPRG7(r4)
	/* r13 has already been saved in the exception handler
	 * use r13 to save the shared pointer
	 */
	PPC_LL	r13, VCPU_SHARED(r4)

	/* Save PMGC0 and Freeze all counters */
	lwz	r9, VCPU_PM_IS_RESERVED(r4)
	cmpwi	r9, 0
	beq	..skip_pmgc0_save
	mfpmr	r9, PMRN_PMGC0
	stw	r9, VCPU_SHADOW_PMGC0(r4)
	lis	r8, PMGC0_FAC@h
	ori	r8, r8, PMGC0_FAC@l
	ori	r9, r9, r8
	mtpmr	PMRN_PMGC0, r9
..skip_pmgc0_save:

	li	r11, 0
	li	r6, 1
	slw	r6, r6, r5
	or.	r6, r6, r6
	bne	..skip_upper_mask_check
	subi	r7, r5, 32
	li	r11, 1
	slw	r11, r11, r7
..skip_upper_mask_check:

	/*
	 * If guest not used debug facility then hw debug registers
	 * already have proper host values. If guest used debug
	 * facility then restore host debug registers.
	 * No Need to save guest debug registers as they are already intact
	 * in guest/shadow registers.
	 */
	addi	r8, r4, VCPU_SHADOW_DBG
	lwz	r9, 0(r8)
	rlwinm	r9, r9, 0, 4, 24
	cmpwi	r9, 0
	beq	..skip_load_host_debug
	addi	r7, r4, VCPU_HOST_DBG - 4
	lwzu	r3, 4(r7)
	lwz	r9, 0(r8)
	andis.	r9, r9, DBCR0_AC_BITS@h
	li	r9, 0
	mtspr	SPRN_DBCR0, r9		/* disable all debug event */
	beq	..skip_load_hw_bkpts
	lwzu	r9, 4(r7)
	mtspr	SPRN_DBCR1, r9
	lwzu	r9, 4(r7)
	mtspr	SPRN_DBCR2, r9
	lwzu	r9, 4(r7)
	mtspr	SPRN_DBCR4, r9
	lwzu	r9, 4(r7)
	mtspr	SPRN_IAC1, r9
	lwzu	r9, 4(r7)
	mtspr	SPRN_IAC2, r9
#ifndef CONFIG_FSL_BOOKE
	lwzu	r9, 4(r7)
	mtspr	SPRN_IAC3, r9
	lwzu	r9, 4(r7)
	mtspr	SPRN_IAC4, r9
#endif
	lwzu	r9, 4(r7)
	mtspr	SPRN_DAC1, r9
	lwzu	r9, 4(r7)
	mtspr	SPRN_DAC2, r9
..skip_load_hw_bkpts:
	isync
	/* Clear h/w DBSR and save current(guest) DBSR */
	mfspr	r8, SPRN_DBSR
	mtspr	SPRN_DBSR, r8
	isync
	andi.	r9, r6, NEED_DBG_SAVE_REGS
	beq	..skip_dbsr_save
	stw	r8, VCPU_DBSR(r4)
..skip_dbsr_save:
	/* Clear EPCR.DUVD and set host DBCR0 */
	mfspr	r8, SPRN_EPCR
	rlwinm	r8, r8, 0, ~EPCR_DUVD
	mtspr	SPRN_EPCR, r8
	isync
	mtspr	SPRN_DBCR0, r3
	isync
..skip_load_host_debug:

#ifdef CONFIG_KVM_EXIT_TIMING
	/* save exit time */
1:
	mfspr	r7, SPRN_TBRU
	mfspr	r8, SPRN_TBRL
	mfspr	r9, SPRN_TBRU
	cmpw	r9, r7
	bne	1b
	PPC_STL	r8, VCPU_TIMING_EXIT_TBL(r4)
	PPC_STL	r9, VCPU_TIMING_EXIT_TBU(r4)
#endif
	mfmsr	r9
	mfsrr1	r3
	mfsrr0	r8

	andi.	r7, r11, NEED_GS_REG_SAVE_MASK
	beq	..skip_gs_reg_save
	mfspr	r3, SPRN_GSRR1
	mfspr	r8, SPRN_GSRR0
..skip_gs_reg_save:
	andi.	r7, r6, NEED_MCHK_SAVE_REGS
	bne	..set_mchk_regs
	andi.	r7, r6, NEED_DBG_SAVE_REGS
	bne	..set_dbg_reg
	andi.	r7, r11, NEED_CRIT_SAVE_REGS_HIGH
	bne	..set_crit_reg
	/* Don't allow guest clearing CE/ME/RI impact
	 * the hypervisor
	 */
	oris	r9, r9, MSR_CE@h
	b	..set_msr
..set_mchk_regs:
	mfspr	r3, SPRN_MCSRR1
	mfspr	r8, SPRN_MCSRR0
	b	..skip_msr
..set_dbg_reg:
	mfspr	r3, SPRN_DSRR1
	mfspr	r8, SPRN_DSRR0
	b	..set_msr
..set_crit_reg:
	mfspr	r3, SPRN_CSRR1
	mfspr	r8, SPRN_CSRR0
..set_msr:
	ori	r9, r9, (MSR_ME | MSR_RI)@l
	mtmsr	r9
..skip_msr:

#ifndef CONFIG_64BIT
	stw	r3, (VCPU_SHARED_MSR + 4)(r13)
#else
	std	r3, (VCPU_SHARED_MSR)(r13)
#endif
	PPC_STL	r8, VCPU_PC(r4)

	andi.	r7, r6, NEED_INST_MASK_LOW
	bne	..save_regs
	andi.	r7, r11, NEED_INST_MASK_HIGH
	beq	..skip_inst_copy
..save_regs:
	PPC_STL	r15, VCPU_GPR(r15)(r4)
	PPC_STL	r16, VCPU_GPR(r16)(r4)
	PPC_STL	r17, VCPU_GPR(r17)(r4)
	PPC_STL	r18, VCPU_GPR(r18)(r4)
	PPC_STL	r19, VCPU_GPR(r19)(r4)
	PPC_STL	r20, VCPU_GPR(r20)(r4)
	PPC_STL	r21, VCPU_GPR(r21)(r4)
	PPC_STL	r22, VCPU_GPR(r22)(r4)
	PPC_STL	r23, VCPU_GPR(r23)(r4)
	PPC_STL	r24, VCPU_GPR(r24)(r4)
	PPC_STL	r25, VCPU_GPR(r25)(r4)
	PPC_STL	r26, VCPU_GPR(r26)(r4)
	PPC_STL	r27, VCPU_GPR(r27)(r4)
	PPC_STL	r28, VCPU_GPR(r28)(r4)
	PPC_STL	r29, VCPU_GPR(r29)(r4)
	PPC_STL	r30, VCPU_GPR(r30)(r4)
	PPC_STL	r31, VCPU_GPR(r31)(r4)
..skip_inst_copy:
	/* save DEAR and ESR */

	andi.	r7, r6, NEED_DEAR_MASK
	beq	..skip_dear
	mfspr	r9, SPRN_DEAR
	PPC_STL	r9, VCPU_FAULT_DEAR(r4)
..skip_dear:

	andi.	r7, r6, NEED_ESR_MASK
	beq	..skip_esr
	mfspr	r9, SPRN_ESR
	PPC_STL	r9, VCPU_FAULT_ESR(r4)
..skip_esr:

	/* Save remaining volatile guest register state to vcpu. */
	PPC_STL	r0, VCPU_GPR(r0)(r4)
	PPC_STL	r1, VCPU_GPR(r1)(r4)
	PPC_STL	r2, VCPU_GPR(r2)(r4)
	PPC_STL	r12, VCPU_GPR(r12)(r4)
	PPC_STL	r14, VCPU_GPR(r14)(r4) /* We need a NV GPR below. */
	mflr	r3
	PPC_STL	r3, VCPU_LR(r4)
	mfxer	r3
	PPC_STL	r3, VCPU_XER(r4)

	/* save guest MAS registers and restore host mas4 & mas6 */
	mfspr	r3, SPRN_MAS0
	stw	r3, VCPU_SHARED_MAS0(r13)
	mfspr	r3, SPRN_MAS1
	stw	r3, VCPU_SHARED_MAS1(r13)
	mfspr	r3, SPRN_MAS2
#ifndef CONFIG_64BIT
	stw	r3, (VCPU_SHARED_MAS2 + 4)(r13)
#else
	std	r3, (VCPU_SHARED_MAS2)(r13)
#endif
	mfspr	r3, SPRN_MAS3
	stw	r3, VCPU_SHARED_MAS7_3+4(r13)
	mfspr	r3, SPRN_MAS4
	stw	r3, VCPU_SHARED_MAS4(r13)
	mfspr	r3, SPRN_MAS6
	stw	r3, VCPU_SHARED_MAS6(r13)
	mfspr	r3, SPRN_MAS7
	stw	r3, VCPU_SHARED_MAS7_3+0(r13)
	lwz	r3, VCPU_HOST_MAS4(r4)
	mtspr	SPRN_MAS4, r3
	lwz	r3, VCPU_HOST_MAS6(r4)
	mtspr	SPRN_MAS6, r3
	mfspr	r3, SPRN_EPCR
	rlwinm	r3, r3, 0, 10, 8
	mtspr	SPRN_EPCR, r3
	isync

	/* Restore host stack pointer */
	PPC_LL	r1, VCPU_HOST_STACK(r4)

	PPC_LL	r2, HOST_R2(r1)

	andi.	r7, r6, NEED_HOST_HANDLER_MASK_LOW
	bne	set_host_handler
	andi.	r7, r11, NEED_HOST_HANDLER_MASK_HIGH
	beq	kvm_return_point

set_host_handler:
	mfspr	r7, SPRN_IVOR4
	cmpwi	r5, BOOKE_INTERRUPT_EXTERNAL
	beq	call_linux_handler
	mfspr	r7, SPRN_IVOR10
	cmpwi	r5, BOOKE_INTERRUPT_DECREMENTER
	beq	call_linux_handler
	mfspr	r7, SPRN_IVOR36
	cmpwi	r5, BOOKE_INTERRUPT_DOORBELL
	beq	call_linux_handler

kvm_return_point:
	/* Switch to kernel stack and jump to handler. */
	PPC_LL	r3, HOST_RUN(r1)
	mr	r14, r4 /* Save vcpu pointer. */
	bl	kvmppc_handle_exit

	/* Restore vcpu pointer and the nonvolatiles we used. */
	mr	r4, r14
	PPC_LL	r14, VCPU_GPR(r14)(r4)

	andi.	r5, r3, RESUME_FLAG_NV
	beq	..skip_nv_load
	PPC_LL	r15, VCPU_GPR(r15)(r4)
	PPC_LL	r16, VCPU_GPR(r16)(r4)
	PPC_LL	r17, VCPU_GPR(r17)(r4)
	PPC_LL	r18, VCPU_GPR(r18)(r4)
	PPC_LL	r19, VCPU_GPR(r19)(r4)
	PPC_LL	r20, VCPU_GPR(r20)(r4)
	PPC_LL	r21, VCPU_GPR(r21)(r4)
	PPC_LL	r22, VCPU_GPR(r22)(r4)
	PPC_LL	r23, VCPU_GPR(r23)(r4)
	PPC_LL	r24, VCPU_GPR(r24)(r4)
	PPC_LL	r25, VCPU_GPR(r25)(r4)
	PPC_LL	r26, VCPU_GPR(r26)(r4)
	PPC_LL	r27, VCPU_GPR(r27)(r4)
	PPC_LL	r28, VCPU_GPR(r28)(r4)
	PPC_LL	r29, VCPU_GPR(r29)(r4)
	PPC_LL	r30, VCPU_GPR(r30)(r4)
	PPC_LL	r31, VCPU_GPR(r31)(r4)
..skip_nv_load:
	/* Should we return to the guest? */
	andi.	r5, r3, RESUME_FLAG_HOST
	beq	lightweight_exit

	srawi	r3, r3, 2 /* Shift -ERR back down. */

heavyweight_exit:
	/* Not returning to guest. */
	/* We already saved guest volatile register state; now save the
	 * non-volatiles. */

	PPC_STL	r15, VCPU_GPR(r15)(r4)
	PPC_STL	r16, VCPU_GPR(r16)(r4)
	PPC_STL	r17, VCPU_GPR(r17)(r4)
	PPC_STL	r18, VCPU_GPR(r18)(r4)
	PPC_STL	r19, VCPU_GPR(r19)(r4)
	PPC_STL	r20, VCPU_GPR(r20)(r4)
	PPC_STL	r21, VCPU_GPR(r21)(r4)
	PPC_STL	r22, VCPU_GPR(r22)(r4)
	PPC_STL	r23, VCPU_GPR(r23)(r4)
	PPC_STL	r24, VCPU_GPR(r24)(r4)
	PPC_STL	r25, VCPU_GPR(r25)(r4)
	PPC_STL	r26, VCPU_GPR(r26)(r4)
	PPC_STL	r27, VCPU_GPR(r27)(r4)
	PPC_STL	r28, VCPU_GPR(r28)(r4)
	PPC_STL	r29, VCPU_GPR(r29)(r4)
	PPC_STL	r30, VCPU_GPR(r30)(r4)
	PPC_STL	r31, VCPU_GPR(r31)(r4)

	/* Load host non-volatile register state from host stack. */
	PPC_LL	r14, HOST_NV_GPR(r14)(r1)
	PPC_LL	r15, HOST_NV_GPR(r15)(r1)
	PPC_LL	r16, HOST_NV_GPR(r16)(r1)
	PPC_LL	r17, HOST_NV_GPR(r17)(r1)
	PPC_LL	r18, HOST_NV_GPR(r18)(r1)
	PPC_LL	r19, HOST_NV_GPR(r19)(r1)
	PPC_LL	r20, HOST_NV_GPR(r20)(r1)
	PPC_LL	r21, HOST_NV_GPR(r21)(r1)
	PPC_LL	r22, HOST_NV_GPR(r22)(r1)
	PPC_LL	r23, HOST_NV_GPR(r23)(r1)
	PPC_LL	r24, HOST_NV_GPR(r24)(r1)
	PPC_LL	r25, HOST_NV_GPR(r25)(r1)
	PPC_LL	r26, HOST_NV_GPR(r26)(r1)
	PPC_LL	r27, HOST_NV_GPR(r27)(r1)
	PPC_LL	r28, HOST_NV_GPR(r28)(r1)
	PPC_LL	r29, HOST_NV_GPR(r29)(r1)
	PPC_LL	r30, HOST_NV_GPR(r30)(r1)
	PPC_LL	r31, HOST_NV_GPR(r31)(r1)

	/* Return to kvm_vcpu_run(). */
	PPC_LL	r4, HOST_STACK_LR(r1)
	addi	r1, r1, HOST_STACK_SIZE
	mtlr	r4
	/* r3 still contains the return code from kvmppc_handle_exit(). */
	blr
call_linux_handler:
	LOAD_REG_IMMEDIATE(r14, kvm_return_point)
	mtsrr0	r14
	mfmsr	r14
	mtsrr1	r14
	mfspr	r14, SPRN_IVPR
	add	r14, r14, r7
	/*once host exception is handled we fall to lightweight exit */
	li	r3, 0
	mtctr	r14
	bctr

/* Registers:
 *  r3: kvm_run pointer
 *  r4: vcpu pointer
 */
_GLOBAL(__kvmppc_vcpu_run)
	stwu	r1, -HOST_STACK_SIZE(r1)
	PPC_STL	r1, VCPU_HOST_STACK(r4)	/* Save stack pointer to vcpu. */

	/* Save host state to stack. */
	PPC_STL	r3, HOST_RUN(r1)
	mflr	r3
	PPC_STL	r3, HOST_STACK_LR(r1)

	/* Save host non-volatile register state to stack. */
	PPC_STL	r14, HOST_NV_GPR(r14)(r1)
	PPC_STL	r15, HOST_NV_GPR(r15)(r1)
	PPC_STL	r16, HOST_NV_GPR(r16)(r1)
	PPC_STL	r17, HOST_NV_GPR(r17)(r1)
	PPC_STL	r18, HOST_NV_GPR(r18)(r1)
	PPC_STL	r19, HOST_NV_GPR(r19)(r1)
	PPC_STL	r20, HOST_NV_GPR(r20)(r1)
	PPC_STL	r21, HOST_NV_GPR(r21)(r1)
	PPC_STL	r22, HOST_NV_GPR(r22)(r1)
	PPC_STL	r23, HOST_NV_GPR(r23)(r1)
	PPC_STL	r24, HOST_NV_GPR(r24)(r1)
	PPC_STL	r25, HOST_NV_GPR(r25)(r1)
	PPC_STL	r26, HOST_NV_GPR(r26)(r1)
	PPC_STL	r27, HOST_NV_GPR(r27)(r1)
	PPC_STL	r28, HOST_NV_GPR(r28)(r1)
	PPC_STL	r29, HOST_NV_GPR(r29)(r1)
	PPC_STL	r30, HOST_NV_GPR(r30)(r1)
	PPC_STL	r31, HOST_NV_GPR(r31)(r1)

	/* Load guest non-volatiles. */
	PPC_LL	r14, VCPU_GPR(r14)(r4)
	PPC_LL	r15, VCPU_GPR(r15)(r4)
	PPC_LL	r16, VCPU_GPR(r16)(r4)
	PPC_LL	r17, VCPU_GPR(r17)(r4)
	PPC_LL	r18, VCPU_GPR(r18)(r4)
	PPC_LL	r19, VCPU_GPR(r19)(r4)
	PPC_LL	r20, VCPU_GPR(r20)(r4)
	PPC_LL	r21, VCPU_GPR(r21)(r4)
	PPC_LL	r22, VCPU_GPR(r22)(r4)
	PPC_LL	r23, VCPU_GPR(r23)(r4)
	PPC_LL	r24, VCPU_GPR(r24)(r4)
	PPC_LL	r25, VCPU_GPR(r25)(r4)
	PPC_LL	r26, VCPU_GPR(r26)(r4)
	PPC_LL	r27, VCPU_GPR(r27)(r4)
	PPC_LL	r28, VCPU_GPR(r28)(r4)
	PPC_LL	r29, VCPU_GPR(r29)(r4)
	PPC_LL	r30, VCPU_GPR(r30)(r4)
	PPC_LL	r31, VCPU_GPR(r31)(r4)


lightweight_exit:
	PPC_STL	r2, HOST_R2(r1)

	mfspr	r3, SPRN_PID
	stw	r3, VCPU_HOST_PID(r4)
	lwz	r3, VCPU_GUEST_PID(r4)
	mtspr	SPRN_PID, r3

	/* Save vcpu pointer for the exception handlers
	 * must be done before loading guest r2.
	 */
	SET_SHADOW_VCPU(r4)

	PPC_LL	r13, VCPU_SHARED(r4)
	/* Save host mas4 and mas6 and load guest MAS registers */
	mfspr	r3, SPRN_MAS4
	stw	r3, VCPU_HOST_MAS4(r4)
	mfspr	r3, SPRN_MAS6
	stw	r3, VCPU_HOST_MAS6(r4)
	lwz	r3, VCPU_SHARED_MAS0(r13)
	lwz	r5, VCPU_SHARED_MAS1(r13)
#ifndef CONFIG_64BIT
	lwz	r6, (VCPU_SHARED_MAS2 + 4)(r13)
#else
	ld	r6, (VCPU_SHARED_MAS2)(r13)
#endif
	lwz	r7, VCPU_SHARED_MAS7_3+4(r13)
	lwz	r8, VCPU_SHARED_MAS4(r13)
	mtspr	SPRN_MAS0, r3
	mtspr	SPRN_MAS1, r5
	mtspr	SPRN_MAS2, r6
	mtspr	SPRN_MAS3, r7
	mtspr	SPRN_MAS4, r8
	lwz	r3, VCPU_SHARED_MAS6(r13)
	lwz	r5, VCPU_SHARED_MAS7_3+0(r13)
	mtspr	SPRN_MAS6, r3
	mtspr	SPRN_MAS7, r5
	/* Disable MAS register updates via exception */
	mfspr	r3, SPRN_EPCR
	oris	r3, r3, EPCR_DMIUH@h
	mtspr	SPRN_EPCR, r3

	mfmsr	r7
	rlwinm	r7, r7, 0, ~MSR_DE
	mtmsr	r7
	/*
	 * Load hw debug registers with guest(shadow) debug registers
	 * if guest is using the debug facility and also set EPCR.DUVD
	 * to not allow debug events in HV mode. Do not change the
	 * debug registers if guest is not using the debug facility.
	 */
	addi	r5, r4, VCPU_SHADOW_DBG
	lwz	r6, 0(r5)
	rlwinm	r6, r6, 0, 4, 24
	cmpwi	r6, 0
	beq	..skip_load_guest_debug
	/* Save host DBCR0 */
	addi	r7, r4, VCPU_HOST_DBG
	mfspr	r8, SPRN_DBCR0
	stw	r8, 0(r7)
	/*
	 * Save host DBCR1/2, IACx and DACx and load guest DBCR1/2,
	 * IACx and DACx if guest using hw breakpoint/watchpoints.
	 */
	lwz	r6, 0(r5)
	andis.	r3, r6, DBCR0_AC_BITS@h
	beq	..skip_hw_bkpts
	mfspr	r8, SPRN_DBCR1
	stwu	r8, 4(r7)
	mfspr	r8, SPRN_DBCR2
	stwu	r8, 4(r7)
	mfspr	r8, SPRN_DBCR4
	stwu	r8, 4(r7)
	mfspr	r8, SPRN_IAC1
	stwu	r8, 4(r7)
	mfspr	r8, SPRN_IAC2
	stwu	r8, 4(r7)
#ifndef CONFIG_FSL_BOOKE
	mfspr	r8, SPRN_IAC3
	stwu	r8, 4(r7)
	mfspr	r8, SPRN_IAC4
	stwu	r8, 4(r7)
#endif
	mfspr	r8, SPRN_DAC1
	stwu	r8, 4(r7)
	mfspr	r8, SPRN_DAC2
	stwu	r8, 4(r7)
	li	r8, 0
	mtspr	SPRN_DBCR0, r8		/* disable all debug event */
	lwzu	r8, 4(r5)
	mtspr	SPRN_DBCR1, r8
	lwzu	r8, 4(r5)
	mtspr	SPRN_DBCR2, r8
	lwzu	r8, 4(r5)
	mtspr	SPRN_DBCR4, r8
	lwzu	r8, 4(r5)
	mtspr	SPRN_IAC1, r8
	lwzu	r8, 4(r5)
	mtspr	SPRN_IAC2, r8
#ifndef CONFIG_FSL_BOOKE
	lwzu	r8, 4(r5)
	mtspr	SPRN_IAC3, r8
	lwzu	r8, 4(r5)
	mtspr	SPRN_IAC4, r8
#endif
	lwzu	r8, 4(r5)
	mtspr	SPRN_DAC1, r8
	lwzu	r8, 4(r5)
	mtspr	SPRN_DAC2, r8
..skip_hw_bkpts:
	/* Set EPCR.DUVD and guest DBCR0 */
	mfspr	r7, SPRN_EPCR
	oris	r7, r7, EPCR_DUVD@h
	mtspr	SPRN_EPCR, r7
	isync
	/* Clear if any deferred debug event */
	mfspr	r8, SPRN_DBSR
	mtspr	SPRN_DBSR, r8
	isync
	/* Restore guest DBSR */
	mtspr	SPRN_DBCR0, r6
	isync
..skip_load_guest_debug:

	/* Load Guest PMGC0 */
	lwz	r9, VCPU_PM_IS_RESERVED(r4)
	cmpwi	r9, 0
	beq	..skip_pmgc0_restore
	lwz	r9, VCPU_SHADOW_PMGC0(r4)
	mtpmr	PMRN_PMGC0, r9

..skip_pmgc0_restore:
	/* Load some guest volatiles. */
	PPC_LL	r0, VCPU_GPR(r0)(r4)
	PPC_LL	r2, VCPU_GPR(r2)(r4)
	PPC_LL	r9, VCPU_GPR(r9)(r4)
	PPC_LL	r10, VCPU_GPR(r10)(r4)
	PPC_LL	r11, VCPU_GPR(r11)(r4)
	PPC_LL	r12, VCPU_GPR(r12)(r4)
	PPC_LL	r13, VCPU_GPR(r13)(r4)
	PPC_LL	r3, VCPU_LR(r4)
	mtlr	r3
	PPC_LL	r3, VCPU_XER(r4)
	mtxer	r3

	PPC_LL	r1, VCPU_GPR(r1)(r4)

	/* Host interrupt handlers may have clobbered these guest-readable
	 * SPRGs, so we need to reload them here with the guest's values. */
	lwz	r3, VCPU_VRSAVE(r4)
	mtspr	SPRN_VRSAVE, r3
	PPC_LL	r3, VCPU_SPRG4(r4)
	mtspr	SPRN_SPRG4W, r3
	PPC_LL	r3, VCPU_SPRG5(r4)
	mtspr	SPRN_SPRG5W, r3
	PPC_LL	r3, VCPU_SPRG6(r4)
	mtspr	SPRN_SPRG6W, r3
	PPC_LL	r3, VCPU_SPRG7(r4)
	mtspr	SPRN_SPRG7W, r3

#ifdef CONFIG_KVM_EXIT_TIMING
	/* save enter time */
1:
	mfspr	r6, SPRN_TBRU
	mfspr	r7, SPRN_TBRL
	mfspr	r8, SPRN_TBRU
	cmpw	r8, r6
	bne	1b
	PPC_STL	r7, VCPU_TIMING_LAST_ENTER_TBL(r4)
	PPC_STL	r8, VCPU_TIMING_LAST_ENTER_TBU(r4)
#endif

	/* Finish loading guest volatiles and jump to guest. */
	PPC_LL	r3, VCPU_CTR(r4)
	mtctr	r3
	PPC_LL	r3, VCPU_CR(r4)
	mtcr	r3
	PPC_LL	r5, VCPU_GPR(r5)(r4)
	PPC_LL	r6, VCPU_GPR(r6)(r4)
	PPC_LL	r7, VCPU_GPR(r7)(r4)
	PPC_LL	r8, VCPU_GPR(r8)(r4)
	PPC_LL	r3, VCPU_PC(r4)
	mtsrr0	r3
	PPC_LL	r3, VCPU_SHARED(r4)
#ifndef CONFIG_64BIT
	lwz	r3, (VCPU_SHARED_MSR + 4)(r3)
#else
	ld	r3, (VCPU_SHARED_MSR)(r3)
#endif
	oris	r3, r3, KVMPPC_MSR_MASK@h
	ori	r3, r3, KVMPPC_MSR_MASK@l
	mtsrr1	r3

	PPC_LL	r3, VCPU_GPR(r3)(r4)
	PPC_LL	r4, VCPU_GPR(r4)(r4)
	rfi


/* Registers:
 *  r3: host exception vector
 */
_GLOBAL(kvmppc_invoke_host_mchk_vector)
	mtctr	r3
	LOAD_REG_IMMEDIATE(r3, kvm_host_excp_return_point)
	mtspr	SPRN_MCSRR0, r3
	mfmsr	r3
	ori	r3, r3, MSR_ME | MSR_RI
	mtspr	SPRN_MCSRR1, r3
	bctr
kvm_host_excp_return_point:
	blr
