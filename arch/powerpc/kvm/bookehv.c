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
 * Copyright (C) 2010-2011 Freescale Semiconductor, Inc. All rights reserved.
 *
 * Author: Varun Sethi <varun.sethi@freescale.com>
 *
 * Description:
 * This file is derived from arch/powerpc/kvm/booke.c
 * by Hollis Blanchard <hollisb@us.ibm.com> &
 *    Christian Ehrhardt <ehrhardt@linux.vnet.ibm.com>
 *
 */

#include <linux/errno.h>
#include <linux/err.h>
#include <linux/kvm_host.h>
#include <linux/gfp.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>

#include <asm/cputable.h>
#include <asm/uaccess.h>
#include <asm/kvm_ppc.h>
#include <asm/guestmemio.h>
#include "timing.h"
#include <asm/cacheflush.h>

#include "booke.h"

#define VM_STAT(x) offsetof(struct kvm, stat.x), KVM_STAT_VM
#define VCPU_STAT(x) offsetof(struct kvm_vcpu, stat.x), KVM_STAT_VCPU

struct kvm_stats_debugfs_item debugfs_entries[] = {
	{ "mmio",       VCPU_STAT(mmio_exits) },
	{ "dcr",        VCPU_STAT(dcr_exits) },
	{ "sig",        VCPU_STAT(signal_exits) },
	{ "itlb_r",     VCPU_STAT(itlb_real_miss_exits) },
	{ "itlb_v",     VCPU_STAT(itlb_virt_miss_exits) },
	{ "dtlb_r",     VCPU_STAT(dtlb_real_miss_exits) },
	{ "dtlb_v",     VCPU_STAT(dtlb_virt_miss_exits) },
	{ "sysc",       VCPU_STAT(syscall_exits) },
	{ "isi",        VCPU_STAT(isi_exits) },
	{ "dsi",        VCPU_STAT(dsi_exits) },
	{ "inst_emu",   VCPU_STAT(emulated_inst_exits) },
	{ "dec",        VCPU_STAT(dec_exits) },
	{ "ext_intr",   VCPU_STAT(ext_intr_exits) },
	{ "halt_wakeup", VCPU_STAT(halt_wakeup) },
	{ NULL }
};

/* TODO: use vcpu_printf() */
void kvmppc_dump_vcpu(struct kvm_vcpu *vcpu)
{
	int i;

	printk("pc:   %08lx msr:  %llx\n", vcpu->arch.pc,
	       (unsigned long long)vcpu->arch.shared->msr);
	printk("srr0:   %llx srr1:  %llx\n",
	       (unsigned long long)vcpu->arch.shared->srr0,
	       (unsigned long long)vcpu->arch.shared->srr1);
	printk("lr:   %08lx ctr:  %08lx\n", vcpu->arch.lr, vcpu->arch.ctr);

	printk("exceptions: %08lx\n", vcpu->arch.pending_exceptions);

	for (i = 0; i < 32; i += 4) {
		printk("gpr%02d: %08lx %08lx %08lx %08lx\n", i,
		       kvmppc_get_gpr(vcpu, i),
		       kvmppc_get_gpr(vcpu, i+1),
		       kvmppc_get_gpr(vcpu, i+2),
		       kvmppc_get_gpr(vcpu, i+3));
	}
}

static void kvmppc_bookehv_queue_irqprio(struct kvm_vcpu *vcpu,
                                       unsigned int priority)
{
	set_bit(priority, &vcpu->arch.pending_exceptions);
}

static void kvmppc_core_queue_dtlb_miss(struct kvm_vcpu *vcpu,
                                        ulong dear_flags, ulong esr_flags)
{
	vcpu->arch.queued_dear = dear_flags;
	vcpu->arch.queued_esr = esr_flags;
	kvmppc_bookehv_queue_irqprio(vcpu, BOOKE_IRQPRIO_DTLB_MISS);
}

static void kvmppc_core_queue_inst_storage(struct kvm_vcpu *vcpu,
                                           ulong esr_flags)
{
	vcpu->arch.queued_esr = esr_flags;
	kvmppc_bookehv_queue_irqprio(vcpu, BOOKE_IRQPRIO_INST_STORAGE);
}

void kvmppc_core_queue_program(struct kvm_vcpu *vcpu, ulong esr_flags)
{
	vcpu->arch.queued_esr = esr_flags;
	kvmppc_bookehv_queue_irqprio(vcpu, BOOKE_IRQPRIO_PROGRAM);
}

void kvmppc_core_queue_dec(struct kvm_vcpu *vcpu)
{
	kvmppc_bookehv_queue_irqprio(vcpu, BOOKE_IRQPRIO_DECREMENTER);
}

int kvmppc_core_pending_dec(struct kvm_vcpu *vcpu)
{
	return test_bit(BOOKE_IRQPRIO_DECREMENTER, &vcpu->arch.pending_exceptions);
}

void kvmppc_core_dequeue_dec(struct kvm_vcpu *vcpu)
{
	clear_bit(BOOKE_IRQPRIO_DECREMENTER, &vcpu->arch.pending_exceptions);
}

void kvmppc_core_queue_external(struct kvm_vcpu *vcpu,
                                struct kvm_interrupt *irq)
{
	kvmppc_bookehv_queue_irqprio(vcpu, BOOKE_IRQPRIO_EXTERNAL);
}

void kvmppc_core_dequeue_external(struct kvm_vcpu *vcpu,
                                  struct kvm_interrupt *irq)
{
	clear_bit(BOOKE_IRQPRIO_EXTERNAL, &vcpu->arch.pending_exceptions);
}

/* Deliver the interrupt of the corresponding priority, if possible. */
static int kvmppc_bookehv_irqprio_deliver(struct kvm_vcpu *vcpu,
                                        unsigned int priority)
{
	int allowed = 0;
	ulong msr_mask;
	bool update_esr = false, update_dear = false;

	switch (priority) {
	case BOOKE_IRQPRIO_DTLB_MISS:
	case BOOKE_IRQPRIO_DATA_STORAGE:
		update_dear = true;
		/* fall through */
	case BOOKE_IRQPRIO_INST_STORAGE:
	case BOOKE_IRQPRIO_PROGRAM:
		update_esr = true;
		/* fall through */
	case BOOKE_IRQPRIO_ITLB_MISS:
	case BOOKE_IRQPRIO_FP_UNAVAIL:
	case BOOKE_IRQPRIO_SPE_UNAVAIL:
	case BOOKE_IRQPRIO_SPE_FP_DATA:
	case BOOKE_IRQPRIO_SPE_FP_ROUND:
	case BOOKE_IRQPRIO_AP_UNAVAIL:
	case BOOKE_IRQPRIO_ALIGNMENT:
		allowed = 1;
		msr_mask = MSR_GS | MSR_CE | MSR_ME | MSR_DE;
		break;
	case BOOKE_IRQPRIO_DECREMENTER:
	case BOOKE_IRQPRIO_EXTERNAL:
	case BOOKE_IRQPRIO_FIT:
		allowed = vcpu->arch.shared->msr & MSR_EE;
		msr_mask = MSR_GS | MSR_CE | MSR_ME | MSR_DE;
		break;
	}

	if (allowed) {
		mtspr(SPRN_GSRR0, vcpu->arch.pc);
		mtspr(SPRN_GSRR1, (unsigned long)vcpu->arch.shared->msr);
		vcpu->arch.pc = vcpu->arch.ivpr | vcpu->arch.ivor[priority];
		if (update_esr == true)
			mtspr(SPRN_GESR, vcpu->arch.queued_esr);
		if (update_dear == true)
			mtspr(SPRN_GDEAR, vcpu->arch.queued_dear);
		vcpu->arch.shared->msr &= msr_mask;

#ifdef CONFIG_KVM_MPIC
		/* Set the guest exception proxy register */
		if (priority == BOOKE_IRQPRIO_EXTERNAL)
			mtspr(SPRN_GEPR, kvmppc_mpic_iack(vcpu->kvm, 0));
#endif
		clear_bit(priority, &vcpu->arch.pending_exceptions);
		if (vcpu->arch.pending_exceptions)
			kvmppc_set_pending_interrupt(vcpu);
	} else {
		/* Mechanism for delivering a pending interrupt
		 * to the guest. In case of e500mc we do this
		 * via guest doorbell.
		 */
		kvmppc_set_pending_interrupt(vcpu);
	}

	return allowed;
}

/* Check pending exceptions and deliver one, if possible. */
void kvmppc_core_deliver_interrupts(struct kvm_vcpu *vcpu)
{
	unsigned long *pending = &vcpu->arch.pending_exceptions;
	unsigned int priority;

	priority = __ffs(*pending);
	while (priority <= BOOKE_IRQPRIO_MAX) {
		if (kvmppc_bookehv_irqprio_deliver(vcpu, priority))
			break;

		priority = find_next_bit(pending,
		                         BITS_PER_BYTE * sizeof(*pending),
		                         priority + 1);
	}
}

static int get_fault_insn(struct kvm_vcpu *vcpu)
{
	int er;

	guestmem_set_insn(vcpu);
	er = guestmem_in32((uint32_t *)vcpu->arch.pc, &vcpu->arch.last_inst);
	if (er != GUESTMEM_OK) {
	printk(KERN_CRIT "%s: instruction fetch at %lx failed (%08x)\n",
		       __func__, vcpu->arch.pc, vcpu->arch.last_inst);
		/* Deliver Program interrupt to guest. */
		vcpu->arch.fault_esr = ESR_PIL;
		kvmppc_core_queue_program(vcpu, vcpu->arch.fault_esr);
		kvmppc_account_exit_stat(vcpu, EMULATED_INST_EXITS);

		return 1;
	}

	return 0;
}

/**
 * kvmppc_handle_exit
 *
 * Return value is in the form (errcode<<2 | RESUME_FLAG_HOST | RESUME_FLAG_NV)
 */
int kvmppc_handle_exit(struct kvm_run *run, struct kvm_vcpu *vcpu,
                       unsigned int exit_nr)
{
	enum emulation_result er;
	int r = RESUME_HOST;

	/* update before a new last_exit_type is rewritten */
	kvmppc_update_timing_stats(vcpu);

	local_irq_enable();

	run->exit_reason = KVM_EXIT_UNKNOWN;
	run->ready_for_interrupt_injection = 1;

	switch (exit_nr) {
	case BOOKE_INTERRUPT_EXTERNAL:
		kvmppc_account_exit(vcpu, EXT_INTR_EXITS);
		kvm_resched(vcpu);
		r = RESUME_GUEST;
		break;

	case BOOKE_INTERRUPT_DECREMENTER:
		kvmppc_account_exit(vcpu, DEC_EXITS);
		kvm_resched(vcpu);
		r = RESUME_GUEST;
		break;

	case BOOKE_INTERRUPT_DOORBELL:
		kvm_resched(vcpu);
		r = RESUME_GUEST;
		break;

	case BOOKE_INTERRUPT_PROGRAM:
		kvmppc_core_queue_program(vcpu, vcpu->arch.fault_esr);
		kvmppc_account_exit(vcpu, PRG_INT_EXITS);
		r = RESUME_GUEST;
		break;

	case BOOKE_HV_GUEST_DBELL:
		/* we are here because there is a pending guest
		 * interrupt which could not be delivered as MSR_EE
		 * was not set. Once we break from here we would again
		 * go to kvmpcc_core_deliver_interrupts
		 */
		vcpu->arch.pc = vcpu->arch.gsrr0;
		vcpu->arch.shared->msr = vcpu->arch.gsrr1;
		r = RESUME_GUEST;
		break;
	/* TBD */
	/*case BOOKE_HV_SYSCALL:*/
	case BOOKE_HV_PRIV:
		er = get_fault_insn(vcpu);
		if (er) {
			r = RESUME_GUEST_NV;
			break;
		}

		er = kvmppc_emulate_instruction(run, vcpu);
		switch (er) {
		case EMULATE_DONE:
			/* don't overwrite subtypes, just account kvm_stats */
			kvmppc_account_exit_stat(vcpu, EMULATED_INST_EXITS);
			/* Future optimization: only reload non-volatiles if
			 * they were actually modified by emulation. */
			r = RESUME_GUEST_NV;
			break;
		case EMULATE_DO_DCR:
			run->exit_reason = KVM_EXIT_DCR;
			r = RESUME_HOST;
			break;
		case EMULATE_FAIL:
			printk(KERN_CRIT "%s: emulation at %lx failed (%08x)\n",
			       __func__, vcpu->arch.pc, vcpu->arch.last_inst);
			/* Deliver Program interrupt to guest. */
			vcpu->arch.fault_esr = ESR_PIL;
			kvmppc_core_queue_program(vcpu, vcpu->arch.fault_esr);
			kvmppc_account_exit_stat(vcpu, EMULATED_INST_EXITS);
			r = RESUME_GUEST_NV;
			break;
		default:
			BUG();
		}
		break;

	case BOOKE_INTERRUPT_FP_UNAVAIL:
		kvmppc_bookehv_queue_irqprio(vcpu, BOOKE_IRQPRIO_FP_UNAVAIL);
		kvmppc_account_exit(vcpu, FP_UNAVAIL);
		r = RESUME_GUEST;
		break;

	case BOOKE_INTERRUPT_SPE_UNAVAIL:
		kvmppc_bookehv_queue_irqprio(vcpu, BOOKE_IRQPRIO_SPE_UNAVAIL);
		r = RESUME_GUEST;
		break;

	case BOOKE_INTERRUPT_SPE_FP_DATA:
		kvmppc_bookehv_queue_irqprio(vcpu, BOOKE_IRQPRIO_SPE_FP_DATA);
		r = RESUME_GUEST;
		break;

	case BOOKE_INTERRUPT_SPE_FP_ROUND:
		kvmppc_bookehv_queue_irqprio(vcpu, BOOKE_IRQPRIO_SPE_FP_ROUND);
		r = RESUME_GUEST;
		break;

	case BOOKE_INTERRUPT_INST_STORAGE:
		kvmppc_core_queue_inst_storage(vcpu, vcpu->arch.fault_esr);
		kvmppc_account_exit(vcpu, ISI_EXITS);
		r = RESUME_GUEST;
		break;

	case BOOKE_INTERRUPT_DTLB_MISS: {
		unsigned long eaddr = vcpu->arch.fault_dear;
		int gtlb_index;
		gpa_t gpaddr;
		gfn_t gfn;

		/* Check the guest TLB. */
		gtlb_index = kvmppc_mmu_dtlb_index(vcpu, eaddr);
		if (gtlb_index < 0) {
			/* The guest didn't have a mapping for it. */
			kvmppc_core_queue_dtlb_miss(vcpu,
			                            vcpu->arch.fault_dear,
			                            vcpu->arch.fault_esr);
			kvmppc_mmu_dtlb_miss(vcpu);
			kvmppc_account_exit(vcpu, DTLB_REAL_MISS_EXITS);
			r = RESUME_GUEST;
			break;
		}

		gpaddr = kvmppc_mmu_xlate(vcpu, gtlb_index, eaddr);
		gfn = gpaddr >> PAGE_SHIFT;

		if (kvm_is_visible_gfn(vcpu->kvm, gfn)) {
			/* The guest TLB had a mapping, but the shadow TLB
			 * didn't, and it is RAM. This could be because:
			 * a) the entry is mapping the host kernel, or
			 * b) the guest used a large mapping which we're faking
			 * Either way, we need to satisfy the fault without
			 * invoking the guest. */
			kvmppc_mmu_map(vcpu, eaddr, gpaddr, gtlb_index);
			kvmppc_account_exit(vcpu, DTLB_VIRT_MISS_EXITS);
			r = RESUME_GUEST;
		} else {
			/* Guest has mapped and accessed a page which is not
			 * actually RAM. */
			er = get_fault_insn(vcpu);
			if (er) {
				r = RESUME_GUEST_NV;
				break;
			}
			vcpu->arch.paddr_accessed = gpaddr;
			r = kvmppc_emulate_mmio(run, vcpu);
			kvmppc_account_exit(vcpu, MMIO_EXITS);
		}

		break;
	}

	case BOOKE_INTERRUPT_ITLB_MISS: {
		unsigned long eaddr = vcpu->arch.pc;
		gpa_t gpaddr;
		gfn_t gfn;
		int gtlb_index;

		r = RESUME_GUEST;

		/* Check the guest TLB. */
		gtlb_index = kvmppc_mmu_itlb_index(vcpu, eaddr);
		if (gtlb_index < 0) {
			/* The guest didn't have a mapping for it. */
			kvmppc_bookehv_queue_irqprio(vcpu, BOOKE_IRQPRIO_ITLB_MISS);
			kvmppc_mmu_itlb_miss(vcpu);
			kvmppc_account_exit(vcpu, ITLB_REAL_MISS_EXITS);
			break;
		}

		kvmppc_account_exit(vcpu, ITLB_VIRT_MISS_EXITS);

		gpaddr = kvmppc_mmu_xlate(vcpu, gtlb_index, eaddr);
		gfn = gpaddr >> PAGE_SHIFT;

		if (kvm_is_visible_gfn(vcpu->kvm, gfn)) {
			/* The guest TLB had a mapping, but the shadow TLB
			 * didn't. This could be because:
			 * a) the entry is mapping the host kernel, or
			 * b) the guest used a large mapping which we're faking
			 * Either way, we need to satisfy the fault without
			 * invoking the guest. */
			kvmppc_mmu_map(vcpu, eaddr, gpaddr, gtlb_index);
		} else {
			/* Guest mapped and leaped at non-RAM! */
			kvmppc_bookehv_queue_irqprio(vcpu, BOOKE_IRQPRIO_MACHINE_CHECK);
		}

		break;
	}

	default:
		printk(KERN_EMERG "exit_nr %d\n", exit_nr);
		BUG();
	}

	local_irq_disable();

	kvmppc_core_deliver_interrupts(vcpu);

	if (!(r & RESUME_HOST)) {
		/* To avoid clobbering exit_reason, only check for signals if
		 * we aren't already exiting to userspace for some other
		 * reason. */
		if (signal_pending(current)) {
			run->exit_reason = KVM_EXIT_INTR;
			r = (-EINTR << 2) | RESUME_HOST | (r & RESUME_FLAG_NV);
			kvmppc_account_exit(vcpu, SIGNAL_EXITS);
		}
	}

	return r;
}

/* Initial guest state: 16MB mapping 0 -> 0, PC = 0, MSR = 0, R1 = 16MB */
int kvm_arch_vcpu_setup(struct kvm_vcpu *vcpu)
{
	int i;

	vcpu->arch.pc = 0;
	vcpu->arch.shared->msr = 0;
	kvmppc_set_gpr(vcpu, 1, (16<<20) - 8); /* -8 for the callee-save LR slot */

	vcpu->arch.shadow_pid = 0;

	/* Eye-catching number so we know if the guest takes an interrupt
	 * before it's programmed its own IVPR. */
	vcpu->arch.ivpr = 0x55550000;
	for (i = 0; i < BOOKE_IRQPRIO_MAX; i++)
		vcpu->arch.ivor[i] = 0x7700 | i * 4;

	kvmppc_init_timing_stats(vcpu);

	return kvmppc_core_vcpu_setup(vcpu);
}

int kvm_arch_vcpu_ioctl_get_regs(struct kvm_vcpu *vcpu, struct kvm_regs *regs)
{
	int i;

	regs->pc = vcpu->arch.pc;
	regs->cr = kvmppc_get_cr(vcpu);
	regs->ctr = vcpu->arch.ctr;
	regs->lr = vcpu->arch.lr;
	regs->xer = kvmppc_get_xer(vcpu);
	regs->msr = vcpu->arch.shared->msr;
	regs->srr0 = vcpu->arch.shared->srr0;
	regs->srr1 = vcpu->arch.shared->srr1;
	regs->pid = vcpu->arch.pid;
	regs->sprg0 = vcpu->arch.shared->sprg0;
	regs->sprg1 = vcpu->arch.shared->sprg1;
	regs->sprg2 = vcpu->arch.shared->sprg2;
	regs->sprg3 = vcpu->arch.shared->sprg3;
	regs->sprg4 = vcpu->arch.sprg4;
	regs->sprg5 = vcpu->arch.sprg5;
	regs->sprg6 = vcpu->arch.sprg6;
	regs->sprg7 = vcpu->arch.sprg7;

	for (i = 0; i < ARRAY_SIZE(regs->gpr); i++)
		regs->gpr[i] = kvmppc_get_gpr(vcpu, i);

	return 0;
}

int kvm_arch_vcpu_ioctl_set_regs(struct kvm_vcpu *vcpu, struct kvm_regs *regs)
{
	int i;

	vcpu->arch.pc = regs->pc;
	vcpu->arch.shared->msr = regs->msr;
	kvmppc_set_cr(vcpu, regs->cr);
	vcpu->arch.ctr = regs->ctr;
	vcpu->arch.lr = regs->lr;
	kvmppc_set_xer(vcpu, regs->xer);
	vcpu->arch.shared->srr0 = regs->srr0;
	vcpu->arch.shared->srr1 = regs->srr1;
	kvmppc_set_pid(vcpu, regs->pid);
	vcpu->arch.shared->sprg0 = regs->sprg0;
	vcpu->arch.shared->sprg1 = regs->sprg1;
	vcpu->arch.shared->sprg2 = regs->sprg2;
	vcpu->arch.shared->sprg3 = regs->sprg3;
	vcpu->arch.sprg4 = regs->sprg4;
	vcpu->arch.sprg5 = regs->sprg5;
	vcpu->arch.sprg6 = regs->sprg6;
	vcpu->arch.sprg7 = regs->sprg7;

	for (i = 0; i < ARRAY_SIZE(regs->gpr); i++)
		kvmppc_set_gpr(vcpu, i, regs->gpr[i]);

	return 0;
}

static void get_sregs_base(struct kvm_vcpu *vcpu,
                           struct kvm_sregs *sregs)
{
	u64 tb = get_tb();

	sregs->u.e.features |= KVM_SREGS_E_BASE;

	sregs->u.e.csrr0 = vcpu->arch.csrr0;
	sregs->u.e.csrr1 = vcpu->arch.csrr1;
	sregs->u.e.mcsr = vcpu->arch.mcsr;
	sregs->u.e.esr = vcpu->arch.shared->esr;
	sregs->u.e.dear = vcpu->arch.shared->dar;
	sregs->u.e.tsr = vcpu->arch.tsr;
	sregs->u.e.tcr = vcpu->arch.tcr;
	sregs->u.e.dec = kvmppc_get_dec(vcpu, tb);
	sregs->u.e.tb = tb;
	sregs->u.e.vrsave = vcpu->arch.vrsave;
}

static int set_sregs_base(struct kvm_vcpu *vcpu,
                          struct kvm_sregs *sregs)
{
	if (!(sregs->u.e.features & KVM_SREGS_E_BASE))
		return 0;

	vcpu->arch.csrr0 = sregs->u.e.csrr0;
	vcpu->arch.csrr1 = sregs->u.e.csrr1;
	vcpu->arch.mcsr = sregs->u.e.mcsr;
	vcpu->arch.shared->esr = sregs->u.e.esr;
	vcpu->arch.shared->dar = sregs->u.e.dear;
	vcpu->arch.vrsave = sregs->u.e.vrsave;
	vcpu->arch.tcr = sregs->u.e.tcr;

	if (sregs->u.e.update_special & KVM_SREGS_E_UPDATE_DEC)
		vcpu->arch.dec = sregs->u.e.dec;

	kvmppc_emulate_dec(vcpu);

	if (sregs->u.e.update_special & KVM_SREGS_E_UPDATE_TSR) {
		/*
		 * FIXME: existing KVM timer handling is incomplete.
		 * TSR cannot be read by the guest, and its value in
		 * vcpu->arch is always zero.  For now, just handle
		 * the case where the caller is trying to inject a
		 * decrementer interrupt.
		 */

		if ((sregs->u.e.tsr & TSR_DIS) &&
		    (vcpu->arch.tcr & TCR_DIE))
			kvmppc_core_queue_dec(vcpu);
	}

	return 0;
}

static void get_sregs_arch206(struct kvm_vcpu *vcpu,
                              struct kvm_sregs *sregs)
{
	sregs->u.e.features |= KVM_SREGS_E_ARCH206;

	sregs->u.e.pir = 0;
	sregs->u.e.mcsrr0 = vcpu->arch.mcsrr0;
	sregs->u.e.mcsrr1 = vcpu->arch.mcsrr1;
	sregs->u.e.decar = vcpu->arch.decar;
	sregs->u.e.ivpr = vcpu->arch.ivpr;
}

static int set_sregs_arch206(struct kvm_vcpu *vcpu,
                             struct kvm_sregs *sregs)
{
	if (!(sregs->u.e.features & KVM_SREGS_E_ARCH206))
		return 0;

	if (sregs->u.e.pir != 0)
		return -EINVAL;

	vcpu->arch.mcsrr0 = sregs->u.e.mcsrr0;
	vcpu->arch.mcsrr1 = sregs->u.e.mcsrr1;
	vcpu->arch.decar = sregs->u.e.decar;
	vcpu->arch.ivpr = sregs->u.e.ivpr;

	return 0;
}

void kvmppc_get_sregs_ivor(struct kvm_vcpu *vcpu, struct kvm_sregs *sregs)
{
	sregs->u.e.features |= KVM_SREGS_E_IVOR;

	sregs->u.e.ivor_low[0] = vcpu->arch.ivor[BOOKE_IRQPRIO_CRITICAL];
	sregs->u.e.ivor_low[1] = vcpu->arch.ivor[BOOKE_IRQPRIO_MACHINE_CHECK];
	sregs->u.e.ivor_low[2] = vcpu->arch.ivor[BOOKE_IRQPRIO_DATA_STORAGE];
	sregs->u.e.ivor_low[3] = vcpu->arch.ivor[BOOKE_IRQPRIO_INST_STORAGE];
	sregs->u.e.ivor_low[4] = vcpu->arch.ivor[BOOKE_IRQPRIO_EXTERNAL];
	sregs->u.e.ivor_low[5] = vcpu->arch.ivor[BOOKE_IRQPRIO_ALIGNMENT];
	sregs->u.e.ivor_low[6] = vcpu->arch.ivor[BOOKE_IRQPRIO_PROGRAM];
	sregs->u.e.ivor_low[7] = vcpu->arch.ivor[BOOKE_IRQPRIO_FP_UNAVAIL];
	sregs->u.e.ivor_low[8] = vcpu->arch.ivor[BOOKE_IRQPRIO_SYSCALL];
	sregs->u.e.ivor_low[9] = vcpu->arch.ivor[BOOKE_IRQPRIO_AP_UNAVAIL];
	sregs->u.e.ivor_low[10] = vcpu->arch.ivor[BOOKE_IRQPRIO_DECREMENTER];
	sregs->u.e.ivor_low[11] = vcpu->arch.ivor[BOOKE_IRQPRIO_FIT];
	sregs->u.e.ivor_low[12] = vcpu->arch.ivor[BOOKE_IRQPRIO_WATCHDOG];
	sregs->u.e.ivor_low[13] = vcpu->arch.ivor[BOOKE_IRQPRIO_DTLB_MISS];
	sregs->u.e.ivor_low[14] = vcpu->arch.ivor[BOOKE_IRQPRIO_ITLB_MISS];
	sregs->u.e.ivor_low[15] = vcpu->arch.ivor[BOOKE_IRQPRIO_DEBUG];
}

int kvmppc_set_sregs_ivor(struct kvm_vcpu *vcpu, struct kvm_sregs *sregs)
{
	if (!(sregs->u.e.features & KVM_SREGS_E_IVOR))
		return 0;

	vcpu->arch.ivor[BOOKE_IRQPRIO_CRITICAL] = sregs->u.e.ivor_low[0];
	vcpu->arch.ivor[BOOKE_IRQPRIO_MACHINE_CHECK] = sregs->u.e.ivor_low[1];
	vcpu->arch.ivor[BOOKE_IRQPRIO_DATA_STORAGE] = sregs->u.e.ivor_low[2];
	vcpu->arch.ivor[BOOKE_IRQPRIO_INST_STORAGE] = sregs->u.e.ivor_low[3];
	vcpu->arch.ivor[BOOKE_IRQPRIO_EXTERNAL] = sregs->u.e.ivor_low[4];
	vcpu->arch.ivor[BOOKE_IRQPRIO_ALIGNMENT] = sregs->u.e.ivor_low[5];
	vcpu->arch.ivor[BOOKE_IRQPRIO_PROGRAM] = sregs->u.e.ivor_low[6];
	vcpu->arch.ivor[BOOKE_IRQPRIO_FP_UNAVAIL] = sregs->u.e.ivor_low[7];
	vcpu->arch.ivor[BOOKE_IRQPRIO_SYSCALL] = sregs->u.e.ivor_low[8];
	vcpu->arch.ivor[BOOKE_IRQPRIO_AP_UNAVAIL] = sregs->u.e.ivor_low[9];
	vcpu->arch.ivor[BOOKE_IRQPRIO_DECREMENTER] = sregs->u.e.ivor_low[10];
	vcpu->arch.ivor[BOOKE_IRQPRIO_FIT] = sregs->u.e.ivor_low[11];
	vcpu->arch.ivor[BOOKE_IRQPRIO_WATCHDOG] = sregs->u.e.ivor_low[12];
	vcpu->arch.ivor[BOOKE_IRQPRIO_DTLB_MISS] = sregs->u.e.ivor_low[13];
	vcpu->arch.ivor[BOOKE_IRQPRIO_ITLB_MISS] = sregs->u.e.ivor_low[14];
	vcpu->arch.ivor[BOOKE_IRQPRIO_DEBUG] = sregs->u.e.ivor_low[15];

	return 0;
}

int kvm_arch_vcpu_ioctl_get_sregs(struct kvm_vcpu *vcpu,
                                  struct kvm_sregs *sregs)
{
	sregs->pvr = vcpu->arch.pvr;

	get_sregs_base(vcpu, sregs);
	get_sregs_arch206(vcpu, sregs);
	kvmppc_core_get_sregs(vcpu, sregs);
	return 0;
}

int kvm_arch_vcpu_ioctl_set_sregs(struct kvm_vcpu *vcpu,
                                  struct kvm_sregs *sregs)
{
	int ret;

	/* Don't allow PVR override, at least for now. */
	if (sregs->pvr != vcpu->arch.pvr)
		return -EINVAL;

	ret = set_sregs_base(vcpu, sregs);
	if (ret < 0)
		return ret;

	ret = set_sregs_arch206(vcpu, sregs);
	if (ret < 0)
		return ret;

	return kvmppc_core_set_sregs(vcpu, sregs);
}


int kvm_arch_vcpu_ioctl_get_fpu(struct kvm_vcpu *vcpu, struct kvm_fpu *fpu)
{
	return -ENOTSUPP;
}

int kvm_arch_vcpu_ioctl_set_fpu(struct kvm_vcpu *vcpu, struct kvm_fpu *fpu)
{
	return -ENOTSUPP;
}

int kvm_arch_vcpu_ioctl_translate(struct kvm_vcpu *vcpu,
                                  struct kvm_translation *tr)
{
	int r;

	r = kvmppc_core_vcpu_translate(vcpu, tr);
	return r;
}

int kvm_vm_ioctl_get_dirty_log(struct kvm *kvm, struct kvm_dirty_log *log)
{
	return -ENOTSUPP;
}

int kvmppc_core_set_guest_debug(struct kvm_vcpu *vcpu,
                                struct kvm_guest_debug *dbg)
{
	return -ENOTSUPP;
}

int __init kvmppc_bookehv_init(void)
{
	return 0;
}

void __exit kvmppc_bookehv_exit(void)
{
	kvm_exit();
}
