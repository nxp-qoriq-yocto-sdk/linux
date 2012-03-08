/*
 * Copyright (C) 2010 Freescale Semiconductor, Inc. All rights reserved.
 *
 * Author: ashish.kalra@freescale.com
 *
 * Description:
 * This file is derived from arch/powerpc/include/asm/kvm_book3s_asm.h
 * by Alexander Graf <agraf@suse.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2, as
 * published by the Free Software Foundation.
 */
#ifndef __ASM_KVM_BOOKE_HV_ASM_H_
#define __ASM_KVM_BOOKE_HV_ASM_H_

#ifdef __ASSEMBLY__

#ifdef CONFIG_KVM_BOOKE_HV

#include <asm/kvm_asm.h>

.macro DO_KVM ivor_nr excp_srr1
	.if (\ivor_nr == BOOKE_INTERRUPT_INST_STORAGE ) || 		\
	    (\ivor_nr == BOOKE_INTERRUPT_DATA_STORAGE) || 		\
	    (\ivor_nr == BOOKE_INTERRUPT_ALIGNMENT) || 			\
	    (\ivor_nr == BOOKE_INTERRUPT_PROGRAM) ||			\
	    (\ivor_nr == BOOKE_INTERRUPT_EXTERNAL) ||			\
	    (\ivor_nr == BOOKE_INTERRUPT_DECREMENTER) ||		\
	    (\ivor_nr == BOOKE_INTERRUPT_DOORBELL) ||    		\
	    (\ivor_nr == BOOKE_INTERRUPT_FP_UNAVAIL) || 		\
	    (\ivor_nr == BOOKE_INTERRUPT_AP_UNAVAIL) || 		\
	    (\ivor_nr == BOOKE_INTERRUPT_DTLB_MISS) || 			\
	    (\ivor_nr == BOOKE_INTERRUPT_ITLB_MISS) ||			\
	    (\ivor_nr == BOOKE_HV_GUEST_DBELL) ||			\
	    (\ivor_nr == BOOKE_HV_SYSCALL) ||				\
	    (\ivor_nr == BOOKE_HV_PRIV) ||				\
	    (\ivor_nr == BOOKE_INTERRUPT_HV_GS_DBELL_CRIT)

BEGIN_FTR_SECTION
	mfspr	r11, \excp_srr1
	andis. 	r11, r11, MSR_GS@h
	/*
	 * NOTE: kvmppc_handler called with r10 in scratch0, CR in r13,
	 * for critical r8 would be saved in sprg2
	 * thread_struct * in r10, r11 as scratch,
	 * saved r11 in thread_struct.normsave[0]
	 * saved r13 in thread_struct.normsave[2]
	 */
	beq	kvmppc_resume_\ivor_nr
	b	kvmppc_handler_\ivor_nr
END_FTR_SECTION_IFSET(CPU_FTR_EMB_HV)
kvmppc_resume_\ivor_nr:
	.elseif (\ivor_nr == BOOKE_INTERRUPT_HV_GS_DBELL_CRIT) ||	\
		(\ivor_nr == BOOKE_INTERRUPT_CRITICAL) ||		\
		(\ivor_nr == BOOKE_INTERRUPT_WATCHDOG) ||		\
		(\ivor_nr == BOOKE_INTERRUPT_DEBUG) ||			\
		(\ivor_nr == BOOKE_INTERRUPT_MACHINE_CHECK)
BEGIN_FTR_SECTION
	mfspr	r11, \excp_srr1
	andis. 	r11, r11, MSR_GS@h
END_FTR_SECTION_IFSET(CPU_FTR_EMB_HV)
	.endif
.endm

.macro EXC_LVL_KVM_BRANCH_IF_GUEST ivor_nr label
	.if (\ivor_nr == BOOKE_INTERRUPT_HV_GS_DBELL_CRIT) ||	\
	    (\ivor_nr == BOOKE_INTERRUPT_CRITICAL) ||		\
	    (\ivor_nr == BOOKE_INTERRUPT_WATCHDOG) ||		\
	    (\ivor_nr == BOOKE_INTERRUPT_DEBUG) ||		\
	    (\ivor_nr == BOOKE_INTERRUPT_MACHINE_CHECK)
	bne	\label
	.endif
.endm

.macro EXC_LVL_KVM_BRANCH_STACK_LABEL ivor_nr label
	.if (\ivor_nr == BOOKE_INTERRUPT_HV_GS_DBELL_CRIT) ||	\
	    (\ivor_nr == BOOKE_INTERRUPT_CRITICAL) ||		\
	    (\ivor_nr == BOOKE_INTERRUPT_WATCHDOG) ||		\
	    (\ivor_nr == BOOKE_INTERRUPT_DEBUG) ||		\
	    (\ivor_nr == BOOKE_INTERRUPT_MACHINE_CHECK)
	\label:
	.endif
.endm

#else

.macro DO_KVM ivor_nr excp_srr1
.endm
.macro EXC_LVL_KVM_BRANCH_IF_GUEST ivor_nr label
.endm
.macro EXC_LVL_KVM_BRANCH_STACK_LABEL ivor_nr label
.endm

#endif /* CONFIG_KVM_E500MC */
#endif /*__ASSEMBLY__ */
#endif /* __ASM_KVM_BOOKE_HV_ASM_H_ */
