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
 * Copyright IBM Corp. 2007
 * Copyright 2010-2011 Freescale Semiconductor, Inc.
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 *          Christian Ehrhardt <ehrhardt@linux.vnet.ibm.com>
 *          Scott Wood <scottwood@freescale.com>
 *          Varun Sethi <varun.sethi@freescale.com>
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
#include <asm/cacheflush.h>
#include <asm/dbell.h>
#include <asm/hw_irq.h>
#include <asm/irq.h>
#include <asm/code-patching.h>

#include "timing.h"
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
	{ "doorbell", VCPU_STAT(dbell_exits) },
	{ "guest doorbell", VCPU_STAT(gdbell_exits) },
#ifdef CONFIG_SPE
	{ "spe_unavail", VCPU_STAT(spe_unavail) },
	{ "spe_fp_data", VCPU_STAT(spe_fp_data) },
	{ "spe_fp_round", VCPU_STAT(spe_fp_round) },
#endif
	{ NULL }
};

/* TODO: use vcpu_printf() */
void kvmppc_dump_vcpu(struct kvm_vcpu *vcpu)
{
	int i;

	printk("pc:   %08lx msr:  %08llx\n", vcpu->arch.pc, vcpu->arch.shared->msr);
	printk("lr:   %08lx ctr:  %08lx\n", vcpu->arch.lr, vcpu->arch.ctr);
	printk("srr0: %08llx srr1: %08llx\n", vcpu->arch.shared->srr0,
					    vcpu->arch.shared->srr1);

	printk("exceptions: %08lx\n", vcpu->arch.pending_exceptions);

	for (i = 0; i < 32; i += 4) {
		printk("gpr%02d: %08lx %08lx %08lx %08lx\n", i,
		       kvmppc_get_gpr(vcpu, i),
		       kvmppc_get_gpr(vcpu, i+1),
		       kvmppc_get_gpr(vcpu, i+2),
		       kvmppc_get_gpr(vcpu, i+3));
	}
}

#ifdef CONFIG_SPE
static void kvmppc_vcpu_disable_spe(struct kvm_vcpu *vcpu)
{
	preempt_disable();
	if (current->thread.regs->msr & MSR_SPE)
		giveup_spe(current);
	vcpu->arch.shadow_msr &= ~MSR_SPE;
	preempt_enable();
}

static void kvmppc_vcpu_enable_spe(struct kvm_vcpu *vcpu)
{
	preempt_disable();
	if (!(current->thread.regs->msr & MSR_SPE)) {
		load_up_spe();
		current->thread.regs->msr |= MSR_SPE;
	}
	vcpu->arch.shadow_msr |= MSR_SPE;
	preempt_enable();
}

static void kvmppc_vcpu_sync_spe(struct kvm_vcpu *vcpu)
{
	if (vcpu->arch.shared->msr & MSR_SPE) {
		if (!(vcpu->arch.shadow_msr & MSR_SPE))
			kvmppc_vcpu_enable_spe(vcpu);
	} else if (vcpu->arch.shadow_msr & MSR_SPE) {
		kvmppc_vcpu_disable_spe(vcpu);
	}
}
#else
static void kvmppc_vcpu_sync_spe(struct kvm_vcpu *vcpu)
{
}
#endif

/*
 * Helper function for "full" MSR writes.  No need to call this if only
 * EE/CE/ME/DE/RI are changing.
 */
void kvmppc_set_msr(struct kvm_vcpu *vcpu, u32 new_msr)
{
	u32 old_msr = vcpu->arch.shared->msr;

#ifdef CONFIG_KVM_BOOKE_HV
	new_msr |= MSR_GS;

	if (vcpu->guest_debug)
		new_msr |= MSR_DE;
#endif

	vcpu->arch.shared->msr = new_msr;

	kvmppc_mmu_msr_notify(vcpu, old_msr);

#ifdef CONFIG_KVM_E500V2
	/* Change PMLCA for all counters if MSR_PR or MSR_PMM changes */
	if (vcpu->arch.pm_is_reserved &&
	    (old_msr ^ new_msr) & (MSR_PMM | MSR_PR)) {
		kvmppc_set_hwpmlca_all(vcpu);
		vcpu->arch.shadow_msr &= ~MSR_PMM;
		vcpu->arch.shadow_msr |= vcpu->arch.shared->msr & MSR_PMM;
	}
#endif

	if ((old_msr ^ new_msr) & MSR_SPE)
		kvmppc_vcpu_sync_spe(vcpu);

	kvmppc_recalc_shadow_dbcr(vcpu);
}

static void kvmppc_booke_queue_irqprio(struct kvm_vcpu *vcpu,
                                       unsigned int priority)
{
	set_bit(priority, &vcpu->arch.pending_exceptions);
}

static void kvmppc_core_queue_dtlb_miss(struct kvm_vcpu *vcpu,
                                        ulong dear_flags, ulong esr_flags)
{
	vcpu->arch.queued_dear = dear_flags;
	vcpu->arch.queued_esr = esr_flags;
	kvmppc_booke_queue_irqprio(vcpu, BOOKE_IRQPRIO_DTLB_MISS);
}

static void kvmppc_core_queue_data_storage(struct kvm_vcpu *vcpu,
                                           ulong dear_flags, ulong esr_flags)
{
	vcpu->arch.queued_dear = dear_flags;
	vcpu->arch.queued_esr = esr_flags;
	kvmppc_booke_queue_irqprio(vcpu, BOOKE_IRQPRIO_DATA_STORAGE);
}

static void kvmppc_core_queue_inst_storage(struct kvm_vcpu *vcpu,
                                           ulong esr_flags)
{
	vcpu->arch.queued_esr = esr_flags;
	kvmppc_booke_queue_irqprio(vcpu, BOOKE_IRQPRIO_INST_STORAGE);
}

void kvmppc_core_queue_program(struct kvm_vcpu *vcpu, ulong esr_flags)
{
	vcpu->arch.queued_esr = esr_flags;
	kvmppc_booke_queue_irqprio(vcpu, BOOKE_IRQPRIO_PROGRAM);
}

void kvmppc_core_queue_dec(struct kvm_vcpu *vcpu)
{
	kvmppc_booke_queue_irqprio(vcpu, BOOKE_IRQPRIO_DECREMENTER);
}

int kvmppc_core_pending_dec(struct kvm_vcpu *vcpu)
{
	return test_bit(BOOKE_IRQPRIO_DECREMENTER, &vcpu->arch.pending_exceptions);
}

void kvmppc_core_dequeue_dec(struct kvm_vcpu *vcpu)
{
	clear_bit(BOOKE_IRQPRIO_DECREMENTER, &vcpu->arch.pending_exceptions);
}

void kvmppc_core_queue_perfmon(struct kvm_vcpu *vcpu)
{
	kvmppc_booke_queue_irqprio(vcpu, BOOKE_IRQPRIO_PERFORMANCE_MONITOR);
}

int kvmppc_core_pending_perfmon(struct kvm_vcpu *vcpu)
{
	return test_bit(BOOKE_IRQPRIO_PERFORMANCE_MONITOR,
					&vcpu->arch.pending_exceptions);
}
void kvmppc_core_dequeue_perfmon(struct kvm_vcpu *vcpu)
{
	clear_bit(BOOKE_IRQPRIO_PERFORMANCE_MONITOR,
					&vcpu->arch.pending_exceptions);
}

void kvmppc_core_queue_external(struct kvm_vcpu *vcpu,
                                struct kvm_interrupt *irq)
{
	unsigned int prio = BOOKE_IRQPRIO_EXTERNAL;

	if (irq->irq == KVM_INTERRUPT_SET_LEVEL)
		prio = BOOKE_IRQPRIO_EXTERNAL_LEVEL;

	kvmppc_booke_queue_irqprio(vcpu, prio);
}

void kvmppc_core_dequeue_external(struct kvm_vcpu *vcpu,
                                  struct kvm_interrupt *irq)
{
	clear_bit(BOOKE_IRQPRIO_EXTERNAL, &vcpu->arch.pending_exceptions);
	clear_bit(BOOKE_IRQPRIO_EXTERNAL_LEVEL, &vcpu->arch.pending_exceptions);
}

void kvmppc_core_queue_watchdog(struct kvm_vcpu *vcpu)
{
	kvmppc_booke_queue_irqprio(vcpu, BOOKE_IRQPRIO_WATCHDOG);
}

void kvmppc_core_dequeue_watchdog(struct kvm_vcpu *vcpu)
{
	clear_bit(BOOKE_IRQPRIO_WATCHDOG, &vcpu->arch.pending_exceptions);
}

void kvmppc_core_queue_debug(struct kvm_vcpu *vcpu)
{
	kvmppc_booke_queue_irqprio(vcpu, BOOKE_IRQPRIO_DEBUG);
}

void kvmppc_core_dequeue_debug(struct kvm_vcpu *vcpu)
{
	clear_bit(BOOKE_IRQPRIO_DEBUG, &vcpu->arch.pending_exceptions);
}

void kvmppc_core_queue_mcheck(struct kvm_vcpu *vcpu)
{
	kvmppc_booke_queue_irqprio(vcpu, BOOKE_IRQPRIO_MACHINE_CHECK);
}

void kvmppc_core_dequeue_mcheck(struct kvm_vcpu *vcpu)
{
	clear_bit(BOOKE_IRQPRIO_MACHINE_CHECK, &vcpu->arch.pending_exceptions);
}

static void set_guest_srr(struct kvm_vcpu *vcpu, unsigned long srr0, u32 srr1)
{
#ifdef CONFIG_KVM_BOOKE_HV
	mtspr(SPRN_GSRR0, srr0);
	mtspr(SPRN_GSRR1, srr1);
#else
	vcpu->arch.shared->srr0 = srr0;
	vcpu->arch.shared->srr1 = srr1;
#endif
}

static void set_guest_csrr(struct kvm_vcpu *vcpu, unsigned long srr0, u32 srr1)
{
	vcpu->arch.csrr0 = srr0;
	vcpu->arch.csrr1 = srr1;
}

static void set_guest_dsrr(struct kvm_vcpu *vcpu, unsigned long srr0, u32 srr1)
{
	if (cpu_has_feature(CPU_FTR_DEBUG_LVL_EXC)) {
		vcpu->arch.dsrr0 = srr0;
		vcpu->arch.dsrr1 = srr1;
	} else {
		set_guest_csrr(vcpu, srr0, srr1);
	}
}

static void set_guest_mcsrr(struct kvm_vcpu *vcpu, unsigned long srr0, u32 srr1)
{
	vcpu->arch.mcsrr0 = srr0;
	vcpu->arch.mcsrr1 = srr1;
}

static unsigned long get_guest_dear(struct kvm_vcpu *vcpu)
{
#ifdef CONFIG_KVM_BOOKE_HV
	return mfspr(SPRN_GDEAR);
#else
	return vcpu->arch.shared->dar;
#endif
}

static void set_guest_dear(struct kvm_vcpu *vcpu, unsigned long dear)
{
#ifdef CONFIG_KVM_BOOKE_HV
	mtspr(SPRN_GDEAR, dear);
#else
	vcpu->arch.shared->dar = dear;
#endif
}

static unsigned long get_guest_esr(struct kvm_vcpu *vcpu)
{
#ifdef CONFIG_KVM_BOOKE_HV
	return mfspr(SPRN_GESR);
#else
	return vcpu->arch.shared->esr;
#endif
}

static void set_guest_esr(struct kvm_vcpu *vcpu, u32 esr)
{
#ifdef CONFIG_KVM_BOOKE_HV
	mtspr(SPRN_GESR, esr);
#else
	vcpu->arch.shared->esr = esr;
#endif
}

/* Deliver the interrupt of the corresponding priority, if possible. */
static int kvmppc_booke_irqprio_deliver(struct kvm_vcpu *vcpu,
                                        unsigned int priority)
{
	int allowed = 0;
	ulong msr_mask = 0;
	bool update_esr = false, update_dear = false;
	ulong crit_raw = vcpu->arch.shared->critical;
	ulong crit_r1 = kvmppc_get_gpr(vcpu, 1);
	bool crit;
	bool keep_irq = false;
	enum int_class int_class;
#ifdef CONFIG_64BIT
	ulong msr_cm = vcpu->arch.epcr & SPRN_EPCR_ICM ? MSR_CM : 0;
#else
	ulong msr_cm = 0;
#endif

	/* Truncate crit indicators in 32 bit mode */
	if (!(vcpu->arch.shared->msr & MSR_SF)) {
		crit_raw &= 0xffffffff;
		crit_r1 &= 0xffffffff;
	}

	/* Critical section when crit == r1 */
	crit = (crit_raw == crit_r1);
	/* ... and we're in supervisor mode */
	crit = crit && !(vcpu->arch.shared->msr & MSR_PR);

	if (priority == BOOKE_IRQPRIO_EXTERNAL_LEVEL) {
		priority = BOOKE_IRQPRIO_EXTERNAL;
		keep_irq = true;
	}

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
	case BOOKE_IRQPRIO_SYSCALL:
	case BOOKE_IRQPRIO_FP_UNAVAIL:
	case BOOKE_IRQPRIO_SPE_UNAVAIL:
	case BOOKE_IRQPRIO_SPE_FP_DATA:
	case BOOKE_IRQPRIO_SPE_FP_ROUND:
	case BOOKE_IRQPRIO_AP_UNAVAIL:
	case BOOKE_IRQPRIO_ALIGNMENT:
		allowed = 1;
		msr_mask = MSR_CE | MSR_ME | MSR_DE;
		int_class = INT_CLASS_NONCRIT;
		break;
#ifdef CONFIG_KVM_BOOKE206_PERFMON
	case BOOKE_IRQPRIO_PERFORMANCE_MONITOR:
		allowed = vcpu->arch.shared->msr & MSR_EE;
		allowed = allowed && !crit;
		msr_mask = MSR_CE|MSR_ME|MSR_DE;
		int_class = INT_CLASS_NONCRIT;
		keep_irq = true;
		break;
#endif
	case BOOKE_IRQPRIO_WATCHDOG:
	case BOOKE_IRQPRIO_CRITICAL:
	case BOOKE_IRQPRIO_DBELL_CRIT:
		allowed = vcpu->arch.shared->msr & MSR_CE;
		allowed = allowed && !crit;
		msr_mask = MSR_ME;
		int_class = INT_CLASS_CRIT;
		break;
	case BOOKE_IRQPRIO_MACHINE_CHECK:
#ifndef CONFIG_KVM_E500V2
		/* In case of e500mc/e5500 the machine check should remain
		 * pending as long as any bit (indicating the machine
		 * check condition)is set in mcsr.
		 */
		keep_irq = true;
#endif
		allowed = vcpu->arch.shared->msr & MSR_ME;
		allowed = allowed && !crit;
		int_class = INT_CLASS_MC;
		break;
	case BOOKE_IRQPRIO_DECREMENTER:
	case BOOKE_IRQPRIO_FIT:
		keep_irq = true;
		/* fall through */
	case BOOKE_IRQPRIO_EXTERNAL:
	case BOOKE_IRQPRIO_DBELL:
		allowed = vcpu->arch.shared->msr & MSR_EE;
		allowed = allowed && !crit;
		msr_mask = MSR_CE | MSR_ME | MSR_DE;
		int_class = INT_CLASS_NONCRIT;
		break;
	case BOOKE_IRQPRIO_DEBUG:
		allowed = vcpu->arch.shared->msr & MSR_DE;
		allowed = allowed && !crit;
		msr_mask = MSR_ME;
		int_class = INT_CLASS_DBG;
		break;
	}

	if (allowed) {
		switch (int_class) {
		case INT_CLASS_NONCRIT:
			set_guest_srr(vcpu, vcpu->arch.pc,
				      vcpu->arch.shared->msr);
			break;
		case INT_CLASS_CRIT:
			set_guest_csrr(vcpu, vcpu->arch.pc,
				       vcpu->arch.shared->msr);
			break;
		case INT_CLASS_DBG:
			set_guest_dsrr(vcpu, vcpu->arch.pc,
				       vcpu->arch.shared->msr);
			break;
		case INT_CLASS_MC:
			set_guest_mcsrr(vcpu, vcpu->arch.pc,
					vcpu->arch.shared->msr);
			break;
		}

		vcpu->arch.pc = vcpu->arch.ivpr | vcpu->arch.ivor[priority];
		if (update_esr == true)
			set_guest_esr(vcpu, vcpu->arch.queued_esr);
		if (update_dear == true)
			set_guest_dear(vcpu, vcpu->arch.queued_dear);
		kvmppc_set_msr(vcpu, (vcpu->arch.shared->msr & msr_mask)
				| msr_cm);

		if (!keep_irq)
			clear_bit(priority, &vcpu->arch.pending_exceptions);

#ifdef CONFIG_KVM_MPIC
		if (priority == BOOKE_IRQPRIO_EXTERNAL)
#ifdef CONFIG_KVM_BOOKE_HV
			if (kvm_mpic_is_using_coreint(vcpu->kvm)) {
				mtspr(SPRN_GEPR,
				    kvmppc_mpic_iack(vcpu->kvm, vcpu->vcpu_id));
			}
#else
			/* FIXME: nicer interface, vcpu, guest-requested */
			if (vcpu->arch.magic_page_ea)
				vcpu->arch.shared->epr =
				    kvmppc_mpic_iack(vcpu->kvm, vcpu->vcpu_id);
#endif
#endif
	}

#ifdef CONFIG_KVM_BOOKE_HV
	/*
	 * If an interrupt is pending but masked, raise a guest doorbell
	 * so that we are notified when the guest enables the relevant
	 * MSR bit.
	 */
	if (vcpu->arch.pending_exceptions & BOOKE_IRQMASK_EE)
		kvmppc_set_pending_interrupt(vcpu, INT_CLASS_NONCRIT);
	if (vcpu->arch.pending_exceptions & BOOKE_IRQMASK_CE)
		kvmppc_set_pending_interrupt(vcpu, INT_CLASS_CRIT);
	if (vcpu->arch.pending_exceptions & BOOKE_IRQMASK_ME)
		kvmppc_set_pending_interrupt(vcpu, INT_CLASS_MC);
#endif

	return allowed;
}

/*
 * The timer system can almost deal with LONG_MAX timeouts, except that
 * when you get very close to LONG_MAX, the slack added can cause overflow.
 *
 * LONG_MAX/2 is a conservative threshold, but it should be adequate for
 * any realistic use.
 */
#define MAX_TIMEOUT (LONG_MAX/2)

/*
 * Return the number of jiffies until the next timeout.  If the timeout is
 * longer than the MAX_TIMEOUT, that we return MAX_TIMEOUT instead.
 */
static unsigned long watchdog_next_timeout(struct kvm_vcpu *vcpu)
{
	unsigned long long tb, mask, nr_jiffies = 0;
	u32 period = TCR_GET_FSL_WP(vcpu->arch.tcr);

	mask = 1ULL << (63 - period);
	tb = get_tb();
	if (tb & mask)
		nr_jiffies += mask;

	nr_jiffies += mask - (tb & (mask - 1));

	if (do_div(nr_jiffies, tb_ticks_per_jiffy))
		nr_jiffies++;

	return min_t(unsigned long long, nr_jiffies, MAX_TIMEOUT);
}

static void arm_next_watchdog(struct kvm_vcpu *vcpu)
{
	unsigned long nr_jiffies;

	nr_jiffies = watchdog_next_timeout(vcpu);
	if (nr_jiffies < MAX_TIMEOUT)
		mod_timer(&vcpu->arch.wdt_timer, jiffies + nr_jiffies);
	else
		del_timer(&vcpu->arch.wdt_timer);
}

void kvmppc_watchdog_func(unsigned long data)
{
	struct kvm_vcpu *vcpu = (struct kvm_vcpu *)data;
	u32 tsr, new_tsr;
	int final;

	do {
		new_tsr = tsr = vcpu->arch.tsr;
		final = 0;

		/* Time out event */
		if (tsr & TSR_ENW) {
			if (tsr & TSR_WIS) {
				new_tsr = (tsr & ~TCR_WRC_MASK) |
					  (vcpu->arch.tcr & TCR_WRC_MASK);
				vcpu->arch.tcr &= ~TCR_WRC_MASK;
				final = 1;
			} else {
				new_tsr = tsr | TSR_WIS;
			}
		} else {
			new_tsr = tsr | TSR_ENW;
		}
	} while (cmpxchg(&vcpu->arch.tsr, tsr, new_tsr) != tsr);

	if (new_tsr & (TSR_WIS | TCR_WRC_MASK)) {
		smp_wmb();
		kvm_make_request(KVM_REQ_PENDING_TIMER, vcpu);
		kvm_vcpu_kick(vcpu);
	}

	/*
	 * Avoid getting a storm of timers if the guest sets
	 * the period very short.  We'll restart it if anything
	 * changes.
	 */
	if (!final)
		arm_next_watchdog(vcpu);
}
static void update_timer_ints(struct kvm_vcpu *vcpu)
{
	if ((vcpu->arch.tcr & TCR_DIE) && (vcpu->arch.tsr & TSR_DIS))
		kvmppc_core_queue_dec(vcpu);
	else
		kvmppc_core_dequeue_dec(vcpu);

	if ((vcpu->arch.tcr & TCR_WIE) && (vcpu->arch.tsr & TSR_WIS))
		kvmppc_core_queue_watchdog(vcpu);
	else
		kvmppc_core_dequeue_watchdog(vcpu);
}

static void kvmppc_core_check_exceptions(struct kvm_vcpu *vcpu)
{
	unsigned long *pending = &vcpu->arch.pending_exceptions;
	unsigned int priority;

	if (vcpu->requests) {
		if (kvm_check_request(KVM_REQ_PENDING_TIMER, vcpu)) {
			smp_mb();
			update_timer_ints(vcpu);
		}
	}

	priority = __ffs(*pending);
	while (priority < BOOKE_IRQPRIO_MAX) {
		if (kvmppc_booke_irqprio_deliver(vcpu, priority))
			break;

		priority = find_next_bit(pending,
		                         BITS_PER_BYTE * sizeof(*pending),
		                         priority + 1);
	}

	/* Tell the guest about our interrupt status */
	vcpu->arch.shared->int_pending = !!*pending;
}

/* Check pending exceptions and deliver one, if possible. */
int kvmppc_core_prepare_to_enter(struct kvm_vcpu *vcpu)
{
	int r = 0;
	WARN_ON_ONCE(!irqs_disabled());

	kvmppc_core_check_exceptions(vcpu);

	if (vcpu->arch.shared->msr & MSR_WE) {
		local_irq_enable();
		kvm_vcpu_block(vcpu);
		clear_bit(KVM_REQ_UNHALT, &vcpu->requests);
		local_irq_disable();

		kvmppc_set_exit_type(vcpu, EMULATED_MTMSRWE_EXITS);
		r = 1;
	};

	return r;
}

/*
 * Common checks before entering the guest world.  Call with interrupts
 * disabled.
 *
 * returns !0 if a signal is pending and check_signal is true
 */
static int kvmppc_prepare_to_enter(struct kvm_vcpu *vcpu)
{
	int r = 0;

	WARN_ON_ONCE(!irqs_disabled());
	while (true) {
		if (need_resched()) {
			local_irq_enable();
			cond_resched();
			local_irq_disable();
			continue;
		}

		if (signal_pending(current)) {
			r = 1;
			break;
		}

		if (kvmppc_core_prepare_to_enter(vcpu)) {
			/* interrupts got enabled in between, so we
			   are back at square 1 */
			continue;
		}

		break;
	}

	return r;
}

int kvmppc_vcpu_run(struct kvm_run *kvm_run, struct kvm_vcpu *vcpu)
{
	int ret;
#ifdef CONFIG_PPC_FPU
	unsigned int fpscr;
	int fpexc_mode;
	u64 fpr[32];
#endif
#ifdef CONFIG_SPE
	ulong evr[32];
	ulong spefscr;
	u64 acc;
#endif

	if (!vcpu->arch.sane) {
		kvm_run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
		return -EINVAL;
	}

	local_irq_disable();
	if (kvmppc_prepare_to_enter(vcpu)) {
		kvm_run->exit_reason = KVM_EXIT_INTR;
		ret = -EINTR;
		goto out;
	}

	if (vcpu->arch.tsr & TCR_WRC_MASK) {
		kvm_run->exit_reason = KVM_EXIT_WDT;
		ret = 0;
		goto out;
	}

	kvm_guest_enter();

#ifdef CONFIG_PPC_FPU
	/* Save userspace FPU state in stack */
	enable_kernel_fp();
	memcpy(fpr, current->thread.fpr, sizeof(current->thread.fpr));
	fpscr = current->thread.fpscr.val;
	fpexc_mode = current->thread.fpexc_mode;

	/* Restore guest FPU state to thread */
	memcpy(current->thread.fpr, vcpu->arch.fpr, sizeof(vcpu->arch.fpr));
	current->thread.fpscr.val = vcpu->arch.fpscr;

	/*
	 * Since we can't trap on MSR_FP in GS-mode, we consider the guest
	 * as always using the FPU.  Kernel usage of FP (via
	 * enable_kernel_fp()) in this thread must not occur while
	 * vcpu->fpu_active is set.
	 */
	vcpu->fpu_active = 1;

	kvmppc_load_guest_fp(vcpu);
#endif

#ifdef CONFIG_SPE
	/* Save userspace SPE state in stack */
	enable_kernel_spe();
	memcpy(evr, current->thread.evr, sizeof(current->thread.evr));
	acc = current->thread.acc;

	/* Restore guest SPE state to thread */
	memcpy(current->thread.evr, vcpu->arch.evr, sizeof(vcpu->arch.evr));
	current->thread.acc = vcpu->arch.acc;

	/* Switch SPEFSCR and load guest SPE state if needed */
	spefscr = mfspr(SPRN_SPEFSCR);
	kvmppc_vcpu_sync_spe(vcpu);
	mtspr(SPRN_SPEFSCR, vcpu->arch.spefscr);
#endif

	ret = __kvmppc_vcpu_run(kvm_run, vcpu);

#ifdef CONFIG_PPC_FPU
	kvmppc_save_guest_fp(vcpu);

	vcpu->fpu_active = 0;

	/* Save guest FPU state from thread */
	memcpy(vcpu->arch.fpr, current->thread.fpr, sizeof(vcpu->arch.fpr));
	vcpu->arch.fpscr = current->thread.fpscr.val;

	/* Restore userspace FPU state from stack */
	memcpy(current->thread.fpr, fpr, sizeof(current->thread.fpr));
	current->thread.fpscr.val = fpscr;
	current->thread.fpexc_mode = fpexc_mode;
#endif

#ifdef CONFIG_SPE
	/* Switch SPEFSCR and save guest SPE state if needed */
	vcpu->arch.spefscr = mfspr(SPRN_SPEFSCR);
	kvmppc_vcpu_disable_spe(vcpu);
	mtspr(SPRN_SPEFSCR, spefscr);

	/* Save guest SPE state from thread */
	memcpy(vcpu->arch.evr, current->thread.evr, sizeof(vcpu->arch.evr));
	vcpu->arch.acc = current->thread.acc;

	/* Restore userspace SPE state from stack */
	memcpy(current->thread.evr, evr, sizeof(current->thread.evr));
	current->thread.spefscr = spefscr;
	current->thread.acc = acc;
#endif

	kvm_guest_exit();

out:
	local_irq_enable();
	return ret;
}

static int emulation_exit(struct kvm_run *run, struct kvm_vcpu *vcpu,
			  int exit_nr)
{
	enum emulation_result er;
	int ret;

	if (unlikely(vcpu->guest_debug & KVM_GUESTDBG_USE_SW_BP) &&
	             (vcpu->arch.last_inst == KVM_INST_GUESTGDB)) {
		run->exit_reason = KVM_EXIT_DEBUG;
		run->debug.arch.pc = vcpu->arch.pc;
		run->debug.arch.exception = exit_nr;
		run->debug.arch.status = 0;
		kvmppc_account_exit(vcpu, DEBUG_EXITS);
		return RESUME_HOST;
	}

	er = kvmppc_emulate_instruction(run, vcpu);
	switch (er) {
	case EMULATE_DONE:
		/* don't overwrite subtypes, just account kvm_stats */
		kvmppc_account_exit_stat(vcpu, EMULATED_INST_EXITS);
		/* Future optimization: only reload non-volatiles if
		 * they were actually modified by emulation. */
		ret = RESUME_GUEST_NV;
		break;

	case EMULATE_DO_DCR:
		run->exit_reason = KVM_EXIT_DCR;
		ret = RESUME_HOST;
		break;

	case EMULATE_FAIL:
		printk(KERN_CRIT "%s: emulation at %lx failed (%08x)\n",
		       __func__, vcpu->arch.pc, vcpu->arch.last_inst);
		/* For debugging, encode the failing instruction and
		 * report it to userspace. */
		run->hw.hardware_exit_reason = ~0ULL << 32;
		run->hw.hardware_exit_reason |= vcpu->arch.last_inst;
		kvmppc_core_queue_program(vcpu, ESR_PIL);
		return RESUME_HOST;

	default:
		BUG();
	}

	if (unlikely(vcpu->guest_debug & KVM_GUESTDBG_ENABLE) &&
	    (vcpu->guest_debug & KVM_GUESTDBG_SINGLESTEP)) {
		run->exit_reason = KVM_EXIT_DEBUG;
		return RESUME_HOST;
	}

	return ret;
}

static int kvmppc_handle_debug(struct kvm_run *run, struct kvm_vcpu *vcpu)
{
#define DBSR_AC		(DBSR_IAC1 | DBSR_IAC2 | DBSR_IAC3 | DBSR_IAC4| \
			 DBSR_DAC1R | DBSR_DAC1W | DBSR_DAC2R | DBSR_DAC2W)
	u32 dbsr;

#ifndef CONFIG_KVM_BOOKE_HV
	if (cpu_has_feature(CPU_FTR_DEBUG_LVL_EXC))
		vcpu->arch.pc = mfspr(SPRN_DSRR0);
	else
		vcpu->arch.pc = mfspr(SPRN_CSRR0);
#endif
	dbsr = vcpu->arch.dbsr;

	if (vcpu->guest_debug == 0) {
		if (dbsr && (vcpu->arch.shared->msr & MSR_DE))
			kvmppc_core_queue_debug(vcpu);

		/* Inject a program interrupt if trap debug is not allowed */
		if ((dbsr & DBSR_TIE) && !(vcpu->arch.shared->msr & MSR_DE))
			kvmppc_core_queue_program(vcpu, ESR_PTR);

		return RESUME_GUEST;
	} else {
		/* Event from guest debug */
		run->debug.arch.pc = vcpu->arch.pc;
		run->debug.arch.status = 0;
		vcpu->arch.dbsr = 0;

		if (dbsr & (DBSR_IAC1 | DBSR_IAC2 | DBSR_IAC3 | DBSR_IAC4)) {
			run->debug.arch.status |= KVMPPC_DEBUG_BREAKPOINT;
		} else {
			if (dbsr & (DBSR_DAC1W | DBSR_DAC2W))
				run->debug.arch.status |= KVMPPC_DEBUG_WATCH_WRITE;
			else if (dbsr & (DBSR_DAC1R | DBSR_DAC2R))
				run->debug.arch.status |= KVMPPC_DEBUG_WATCH_READ;
			if (dbsr & (DBSR_DAC1R | DBSR_DAC1W))
				run->debug.arch.pc = vcpu->arch.shadow_dbg_reg.dac[0];
			else if (dbsr & (DBSR_DAC2R | DBSR_DAC2W))
				run->debug.arch.pc = vcpu->arch.shadow_dbg_reg.dac[1];
		}

		return RESUME_HOST;
	}
}

static void kvmppc_fill_pt_regs(struct pt_regs *regs)
{
	ulong r1, ip, msr, lr;

	asm("mr %0, 1" : "=r"(r1));
	asm("mflr %0" : "=r"(lr));
	asm("mfmsr %0" : "=r"(msr));
	asm("bl 1f; 1: mflr %0" : "=r"(ip));

	memset(regs, 0, sizeof(*regs));
	regs->gpr[1] = r1;
	regs->nip = ip;
	regs->msr = msr;
	regs->link = lr;
}

/*
 * For interrupts needed to be handled by host interrupt handlers,
 * corresponding host handler are called from here in similar way
 * (but not exact) as they are called from low level handler
 * (such as from arch/powerpc/kernel/head_fsl_booke.S).
 */
static void kvmppc_restart_interrupt(struct kvm_vcpu *vcpu,
				     unsigned int exit_nr)
{
	struct pt_regs regs;

	switch (exit_nr) {
	case BOOKE_INTERRUPT_EXTERNAL:
		kvmppc_fill_pt_regs(&regs);
		do_IRQ(&regs);
		break;
	case BOOKE_INTERRUPT_DECREMENTER:
		kvmppc_fill_pt_regs(&regs);
		timer_interrupt(&regs);
		break;
#if defined(CONFIG_PPC_FSL_BOOK3E) || defined(CONFIG_PPC_BOOK3E_64)
	case BOOKE_INTERRUPT_DOORBELL:
		kvmppc_fill_pt_regs(&regs);
		doorbell_exception(&regs);
		break;
#endif
	case BOOKE_INTERRUPT_MACHINE_CHECK:
		kvmppc_fill_pt_regs(&regs);
		machine_check_exception(&regs);
		break;
	case BOOKE_INTERRUPT_PERFORMANCE_MONITOR:
		kvmppc_fill_pt_regs(&regs);
		performance_monitor_exception(&regs);
		break;
	case BOOKE_INTERRUPT_WATCHDOG:
		kvmppc_fill_pt_regs(&regs);
#ifdef CONFIG_BOOKE_WDT
		WatchdogException(&regs);
#else
		unknown_exception(&regs);
#endif
		break;
	case BOOKE_INTERRUPT_CRITICAL:
		unknown_exception(&regs);
		break;
	}
}

/**
 * kvmppc_handle_exit
 *
 * Return value is in the form (errcode<<2 | RESUME_FLAG_HOST | RESUME_FLAG_NV)
 */
int kvmppc_handle_exit(struct kvm_run *run, struct kvm_vcpu *vcpu,
                       unsigned int exit_nr)
{
	int r = RESUME_HOST;

	/* update before a new last_exit_type is rewritten */
	kvmppc_update_timing_stats(vcpu);

	/* restart interrupts if they were meant for the host */
	kvmppc_restart_interrupt(vcpu, exit_nr);

	if (likely(exit_nr != BOOKE_INTERRUPT_MACHINE_CHECK))
		local_irq_enable();

	run->exit_reason = KVM_EXIT_UNKNOWN;
	run->ready_for_interrupt_injection = 1;

	switch (exit_nr) {
	case BOOKE_INTERRUPT_MACHINE_CHECK:
		r = RESUME_GUEST;
		break;

	case BOOKE_INTERRUPT_EXTERNAL:
		kvmppc_account_exit(vcpu, EXT_INTR_EXITS);
		r = RESUME_GUEST;
		break;

	case BOOKE_INTERRUPT_DECREMENTER:
		kvmppc_account_exit(vcpu, DEC_EXITS);
		r = RESUME_GUEST;
		break;

	case BOOKE_INTERRUPT_WATCHDOG:
		r = RESUME_GUEST;
		break;

	case BOOKE_INTERRUPT_DOORBELL:
		kvmppc_account_exit(vcpu, DBELL_EXITS);
		r = RESUME_GUEST;
		break;

	case BOOKE_INTERRUPT_GUEST_DBELL_CRIT:
		kvmppc_account_exit(vcpu, GDBELL_EXITS);

		/*
		 * We are here because there is a pending guest interrupt
		 * which could not be delivered as MSR_CE or MSR_ME was not
		 * set.  Once we break from here we will retry delivery.
		 */
		r = RESUME_GUEST;
		break;

	case BOOKE_INTERRUPT_GUEST_DBELL:
		kvmppc_account_exit(vcpu, GDBELL_EXITS);

		/*
		 * We are here because there is a pending guest interrupt
		 * which could not be delivered as MSR_EE was not set.  Once
		 * we break from here we will retry delivery.
		 */
		r = RESUME_GUEST;
		break;

	case BOOKE_INTERRUPT_HV_PRIV:
		r = emulation_exit(run, vcpu, exit_nr);
		break;

	case BOOKE_INTERRUPT_PROGRAM:
		if (vcpu->arch.shared->msr & (MSR_PR | MSR_GS)) {
			/*
			 * Program traps generated by user-level software must
			 * be handled by the guest kernel.
			 *
			 * In GS mode, hypervisor privileged instructions trap
			 * on BOOKE_INTERRUPT_HV_PRIV, not here, so these are
			 * actual program interrupts, handled by the guest.
			 */
			kvmppc_core_queue_program(vcpu, vcpu->arch.fault_esr);
			r = RESUME_GUEST;
			kvmppc_account_exit(vcpu, USR_PR_INST);
			break;
		}

		r = emulation_exit(run, vcpu, exit_nr);

		break;

	case BOOKE_INTERRUPT_PERFORMANCE_MONITOR:
		kvm_resched(vcpu);
		kvmppc_account_exit(vcpu, PERFMON_EXITS);
		r = RESUME_GUEST;
		break;

	case BOOKE_INTERRUPT_FP_UNAVAIL:
		kvmppc_booke_queue_irqprio(vcpu, BOOKE_IRQPRIO_FP_UNAVAIL);
		kvmppc_account_exit(vcpu, FP_UNAVAIL);
		r = RESUME_GUEST;
		break;

#ifdef CONFIG_SPE
	case BOOKE_INTERRUPT_SPE_UNAVAIL: {
		if (vcpu->arch.shared->msr & MSR_SPE)
			kvmppc_vcpu_enable_spe(vcpu);
		else
			kvmppc_booke_queue_irqprio(vcpu,
						   BOOKE_IRQPRIO_SPE_UNAVAIL);
		kvmppc_account_exit(vcpu, SPE_UNAVAIL);
		r = RESUME_GUEST;
		break;
	}

	case BOOKE_INTERRUPT_SPE_FP_DATA:
		kvmppc_booke_queue_irqprio(vcpu, BOOKE_IRQPRIO_SPE_FP_DATA);
		kvmppc_account_exit(vcpu, SPE_FP_DATA);
		r = RESUME_GUEST;
		break;

	case BOOKE_INTERRUPT_SPE_FP_ROUND:
		kvmppc_booke_queue_irqprio(vcpu, BOOKE_IRQPRIO_SPE_FP_ROUND);
		kvmppc_account_exit(vcpu, SPE_FP_ROUND);
		r = RESUME_GUEST;
		break;
#else
	case BOOKE_INTERRUPT_SPE_UNAVAIL:
		/*
		 * Guest wants SPE, but host kernel doesn't support it.  Send
		 * an "unimplemented operation" program check to the guest.
		 */
		kvmppc_core_queue_program(vcpu, ESR_PUO | ESR_SPV);
		r = RESUME_GUEST;
		break;

	/*
	 * These really should never happen without CONFIG_SPE,
	 * as we should never enable the real MSR[SPE] in the guest.
	 */
	case BOOKE_INTERRUPT_SPE_FP_DATA:
	case BOOKE_INTERRUPT_SPE_FP_ROUND:
		printk(KERN_CRIT "%s: unexpected SPE interrupt %u at %08lx\n",
		       __func__, exit_nr, vcpu->arch.pc);
		run->hw.hardware_exit_reason = exit_nr;
		r = RESUME_HOST;
		break;
#endif

	case BOOKE_INTERRUPT_DATA_STORAGE:
		kvmppc_core_queue_data_storage(vcpu, vcpu->arch.fault_dear,
		                               vcpu->arch.fault_esr);
		kvmppc_account_exit(vcpu, DSI_EXITS);
		r = RESUME_GUEST;
		break;

	case BOOKE_INTERRUPT_INST_STORAGE:
		kvmppc_core_queue_inst_storage(vcpu, vcpu->arch.fault_esr);
		kvmppc_account_exit(vcpu, ISI_EXITS);
		r = RESUME_GUEST;
		break;

#ifdef CONFIG_KVM_BOOKE_HV
	case BOOKE_INTERRUPT_HV_SYSCALL:
		if (!(vcpu->arch.shared->msr & MSR_PR)) {
			kvmppc_set_gpr(vcpu, 3, kvmppc_kvm_pv(vcpu));
		} else {
			/*
			 * hcall from guest userspace -- send privileged
			 * instruction program check.
			 */
			kvmppc_core_queue_program(vcpu, ESR_PPR);
		}

		r = RESUME_GUEST;
		break;
#else
	case BOOKE_INTERRUPT_SYSCALL:
		if (!(vcpu->arch.shared->msr & MSR_PR) &&
		    (((u32)kvmppc_get_gpr(vcpu, 0)) == KVM_SC_MAGIC_R0)) {
			/* KVM PV hypercalls */
			kvmppc_set_gpr(vcpu, 3, kvmppc_kvm_pv(vcpu));
			r = RESUME_GUEST;
		} else {
			/* Guest syscalls */
			kvmppc_booke_queue_irqprio(vcpu, BOOKE_IRQPRIO_SYSCALL);
		}
		kvmppc_account_exit(vcpu, SYSCALL_EXITS);
		r = RESUME_GUEST;
		break;
#endif

	case BOOKE_INTERRUPT_DTLB_MISS: {
		unsigned long eaddr = vcpu->arch.fault_dear;
		int gtlb_index;
		gpa_t gpaddr;
		gfn_t gfn;

#ifdef CONFIG_KVM_E500V2
		if (!(vcpu->arch.shared->msr & MSR_PR) &&
		    (eaddr & PAGE_MASK) == vcpu->arch.magic_page_ea) {
			kvmppc_map_magic(vcpu);
			kvmppc_account_exit(vcpu, DTLB_VIRT_MISS_EXITS);
			r = RESUME_GUEST;

			break;
		}
#endif

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
			kvmppc_booke_queue_irqprio(vcpu, BOOKE_IRQPRIO_ITLB_MISS);
			kvmppc_mmu_itlb_miss(vcpu);
			kvmppc_account_exit(vcpu, ITLB_REAL_MISS_EXITS);
			break;
		}

		kvmppc_account_exit(vcpu, ITLB_VIRT_MISS_EXITS);

		gpaddr = kvmppc_mmu_xlate(vcpu, gtlb_index, eaddr);
		gfn = gpaddr >> PAGE_SHIFT;

		if (!kvm_is_visible_gfn(vcpu->kvm, gfn)) {
			/* Guest mapped and leaped at non-RAM! */
			u32 ret;

			ret = kvmppc_get_bad_ifetch_mcsr();
			run->ex.exception = BOOKE_INTERRUPT_MACHINE_CHECK;
			run->ex.error_code = ret;
			run->ex.addr = gpaddr;
			run->ex.addr_type = KVM_EX_ADDR_PHYSICAL;
			run->exit_reason = KVM_EXIT_EXCEPTION;
			r = RESUME_HOST;
			break;
		}

		/* The guest TLB had a mapping, but the shadow TLB
		 * didn't. This could be because:
		 * a) the entry is mapping the host kernel, or
		 * b) the guest used a large mapping which we're faking
		 * Either way, we need to satisfy the fault without
		 * invoking the guest. */
		kvmppc_mmu_map(vcpu, eaddr, gpaddr, gtlb_index);

		break;
	}

	case BOOKE_INTERRUPT_DEBUG:
		r = kvmppc_handle_debug(run, vcpu);
		if (r == RESUME_HOST) {
			run->debug.arch.exception = exit_nr;
			run->exit_reason = KVM_EXIT_DEBUG;
		}
		kvmppc_account_exit(vcpu, DEBUG_EXITS);
		break;

	default:
		printk(KERN_EMERG "exit_nr %d\n", exit_nr);
		BUG();
	}

	/*
	 * To avoid clobbering exit_reason, only check for signals if we
	 * aren't already exiting to userspace for some other reason.
	 */
	if (!(r & RESUME_HOST)) {
		local_irq_disable();
		if (kvmppc_prepare_to_enter(vcpu)) {
			run->exit_reason = KVM_EXIT_INTR;
			r = (-EINTR << 2) | RESUME_HOST | (r & RESUME_FLAG_NV);
			kvmppc_account_exit(vcpu, SIGNAL_EXITS);
		}
	}
	if (vcpu->arch.tsr & TCR_WRC_MASK) {
		run->exit_reason = KVM_EXIT_WDT;
		r = RESUME_HOST | (r & RESUME_FLAG_NV);
	}

	return r;
}

/* Initial guest state: 16MB mapping 0 -> 0, PC = 0, MSR = 0, R1 = 16MB */
int kvm_arch_vcpu_setup(struct kvm_vcpu *vcpu)
{
	int i;
	int r;

	vcpu->arch.pc = 0;
	vcpu->arch.shared->pir = vcpu->vcpu_id;
	kvmppc_set_gpr(vcpu, 1, (16<<20) - 8); /* -8 for the callee-save LR slot */
	kvmppc_set_msr(vcpu, 0);

#ifndef CONFIG_KVM_BOOKE_HV
	vcpu->arch.shadow_msr = MSR_USER | MSR_DE | MSR_IS | MSR_DS;
	vcpu->arch.shadow_pid = 1;
	vcpu->arch.shared->msr = 0;
#endif

	/* Eye-catching numbers so we know if the guest takes an interrupt
	 * before it's programmed its own IVPR/IVORs. */
	vcpu->arch.ivpr = 0x55550000;
	for (i = 0; i < BOOKE_IRQPRIO_MAX; i++)
		vcpu->arch.ivor[i] = 0x7700 | i * 4;

	kvmppc_init_timing_stats(vcpu);

	r = kvmppc_core_vcpu_setup(vcpu);
	kvmppc_sanity_check(vcpu);
	return r;
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
	regs->sprg4 = vcpu->arch.shared->sprg4;
	regs->sprg5 = vcpu->arch.shared->sprg5;
	regs->sprg6 = vcpu->arch.shared->sprg6;
	regs->sprg7 = vcpu->arch.shared->sprg7;

	for (i = 0; i < ARRAY_SIZE(regs->gpr); i++)
		regs->gpr[i] = kvmppc_get_gpr(vcpu, i);

	return 0;
}

int kvm_arch_vcpu_ioctl_set_regs(struct kvm_vcpu *vcpu, struct kvm_regs *regs)
{
	int i;

	vcpu->arch.pc = regs->pc;
	kvmppc_set_cr(vcpu, regs->cr);
	vcpu->arch.ctr = regs->ctr;
	vcpu->arch.lr = regs->lr;
	kvmppc_set_xer(vcpu, regs->xer);
	kvmppc_set_msr(vcpu, regs->msr);
	vcpu->arch.shared->srr0 = regs->srr0;
	vcpu->arch.shared->srr1 = regs->srr1;
	kvmppc_set_pid(vcpu, regs->pid);
	vcpu->arch.shared->sprg0 = regs->sprg0;
	vcpu->arch.shared->sprg1 = regs->sprg1;
	vcpu->arch.shared->sprg2 = regs->sprg2;
	vcpu->arch.shared->sprg3 = regs->sprg3;
	vcpu->arch.shared->sprg4 = regs->sprg4;
	vcpu->arch.shared->sprg5 = regs->sprg5;
	vcpu->arch.shared->sprg6 = regs->sprg6;
	vcpu->arch.shared->sprg7 = regs->sprg7;

	for (i = 0; i < ARRAY_SIZE(regs->gpr); i++)
		kvmppc_set_gpr(vcpu, i, regs->gpr[i]);

	return 0;
}

static void get_sregs_base(struct kvm_vcpu *vcpu,
                           struct kvm_sregs *sregs)
{
	u64 tb = get_tb();

	sregs->u.e.features |= KVM_SREGS_E_BASE;
#ifdef CONFIG_64BIT
	sregs->u.e.features |= KVM_SREGS_E_64;
#endif

	sregs->u.e.csrr0 = vcpu->arch.csrr0;
	sregs->u.e.csrr1 = vcpu->arch.csrr1;
	sregs->u.e.mcsr = vcpu->arch.mcsr;
	sregs->u.e.esr = get_guest_esr(vcpu);
	sregs->u.e.dear = get_guest_dear(vcpu);
	sregs->u.e.tsr = vcpu->arch.tsr;
	sregs->u.e.tcr = vcpu->arch.tcr;
	sregs->u.e.dec = kvmppc_get_dec(vcpu, tb);
	sregs->u.e.tb = tb;
	sregs->u.e.vrsave = vcpu->arch.vrsave;
#ifdef CONFIG_64BIT
	sregs->u.e.epcr = vcpu->arch.epcr;
#endif
}

static int set_sregs_base(struct kvm_vcpu *vcpu,
                          struct kvm_sregs *sregs)
{
	if (!(sregs->u.e.features & KVM_SREGS_E_BASE))
		return 0;

	vcpu->arch.csrr0 = sregs->u.e.csrr0;
	vcpu->arch.csrr1 = sregs->u.e.csrr1;
	set_guest_esr(vcpu, sregs->u.e.esr);
	set_guest_dear(vcpu, sregs->u.e.dear);
	vcpu->arch.vrsave = sregs->u.e.vrsave;
	kvmppc_set_tcr(vcpu, sregs->u.e.tcr);

	if (sregs->u.e.update_special & KVM_SREGS_E_UPDATE_MCSR) {
		vcpu->arch.mcsr = sregs->u.e.mcsr;
#ifndef CONFIG_KVM_E500V2
		if (vcpu->arch.mcsr)
			kvmppc_core_queue_mcheck(vcpu);
		else
			kvmppc_core_dequeue_mcheck(vcpu);
#endif
	}

	if (sregs->u.e.update_special & KVM_SREGS_E_UPDATE_DEC) {
		vcpu->arch.dec = sregs->u.e.dec;
		kvmppc_emulate_dec(vcpu);
	}

	if (sregs->u.e.update_special & KVM_SREGS_E_UPDATE_TSR) {
		u32 old_tsr = vcpu->arch.tsr;

		vcpu->arch.tsr = sregs->u.e.tsr;

		if ((old_tsr ^ vcpu->arch.tsr) &
		    (TSR_ENW | TSR_WIS | TCR_WRC_MASK))
			arm_next_watchdog(vcpu);

		update_timer_ints(vcpu);
	}

	return 0;
}

static void get_sregs_arch206(struct kvm_vcpu *vcpu,
                              struct kvm_sregs *sregs)
{
	sregs->u.e.features |= KVM_SREGS_E_ARCH206;

	sregs->u.e.pir = vcpu->vcpu_id;
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

	if (sregs->u.e.pir != vcpu->vcpu_id)
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

	if (vcpu->arch.pvr != sregs->pvr)
		return -EINVAL;

	ret = set_sregs_base(vcpu, sregs);
	if (ret < 0)
		return ret;

	ret = set_sregs_arch206(vcpu, sregs);
	if (ret < 0)
		return ret;

	return kvmppc_core_set_sregs(vcpu, sregs);
}

int kvm_vcpu_ioctl_get_one_reg(struct kvm_vcpu *vcpu, struct kvm_one_reg *reg)
{
	return -EINVAL;
}

int kvm_vcpu_ioctl_set_one_reg(struct kvm_vcpu *vcpu, struct kvm_one_reg *reg)
{
	return -EINVAL;
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

int kvmppc_core_prepare_memory_region(struct kvm *kvm,
				      struct kvm_userspace_memory_region *mem)
{
	return 0;
}

void kvmppc_core_commit_memory_region(struct kvm *kvm,
				struct kvm_userspace_memory_region *mem)
{
}

void kvmppc_set_tcr(struct kvm_vcpu *vcpu, u32 new_tcr)
{
	vcpu->arch.tcr = new_tcr;
	arm_next_watchdog(vcpu);
	update_timer_ints(vcpu);
}

void kvmppc_set_tsr_bits(struct kvm_vcpu *vcpu, u32 tsr_bits)
{
	set_bits(tsr_bits, &vcpu->arch.tsr);
	smp_wmb();
	kvm_make_request(KVM_REQ_PENDING_TIMER, vcpu);
	kvm_vcpu_kick(vcpu);
}

void kvmppc_clr_tsr_bits(struct kvm_vcpu *vcpu, u32 tsr_bits)
{
	clear_bits(tsr_bits, &vcpu->arch.tsr);

	/*
	 * We may have stopped the watchdog due to
	 * being stuck on final expiration.
	 */
	if (tsr_bits & (TSR_ENW | TSR_WIS | TCR_WRC_MASK))
		arm_next_watchdog(vcpu);

	update_timer_ints(vcpu);
}

void kvmppc_decrementer_func(unsigned long data)
{
	struct kvm_vcpu *vcpu = (struct kvm_vcpu *)data;

	if (vcpu->arch.tcr & TCR_ARE) {
		vcpu->arch.dec = vcpu->arch.decar;
		kvmppc_emulate_dec(vcpu);
	}

	kvmppc_set_tsr_bits(vcpu, TSR_DIS);
}

void kvmppc_booke_vcpu_load(struct kvm_vcpu *vcpu, int cpu)
{
	current->thread.kvm_vcpu = vcpu;
}

void kvmppc_booke_vcpu_put(struct kvm_vcpu *vcpu)
{
	current->thread.kvm_vcpu = NULL;
}

#define BP_NUM	KVMPPC_IAC_NUM
#define WP_NUM	KVMPPC_DAC_NUM
void kvmppc_recalc_shadow_ac(struct kvm_vcpu *vcpu)
{
	/*
	 * If debug resources are taken by host (say QEMU) then
	 * debug resources are not available to guest. For Guest
	 * it is like external debugger have taken the resources.
	 */
	if (vcpu->guest_debug == 0) {
		struct kvmppc_debug_reg *sreg = &(vcpu->arch.shadow_dbg_reg),
		                        *greg = &(vcpu->arch.dbg_reg);
		int i;

		for (i = 0; i < BP_NUM; i++)
			sreg->iac[i] = greg->iac[i];
		for (i = 0; i < WP_NUM; i++)
			sreg->dac[i] = greg->dac[i];
	}
}

void kvmppc_recalc_shadow_dbcr(struct kvm_vcpu *vcpu)
{
#define MASK_EVENT (DBCR0_IC | DBCR0_BRT)
	/*
	 * If debug resources are taken by host (say QEMU) then
	 * debug resources are not available to guest. For Guest
	 * it is like external debugger have taken the resources.
	 */
	if (vcpu->guest_debug == 0) {
		struct kvmppc_debug_reg *sreg = &(vcpu->arch.shadow_dbg_reg),
		                        *greg = &(vcpu->arch.dbg_reg);

		sreg->dbcr0 = greg->dbcr0;
		sreg->dbcr1 = greg->dbcr1;
		sreg->dbcr2 = greg->dbcr2;

#ifndef CONFIG_KVM_BOOKE_HV
		/*
		 * Some event should not occur if MSR[DE] = 0,
		 * since MSR[DE] is always set in shadow,
		 * we disable these events in shadow when guest MSR[DE] = 0
		 */
		if (!(vcpu->arch.shared->msr & MSR_DE))
			sreg->dbcr0 = greg->dbcr0 & ~MASK_EVENT;

		/* XXX assume that guest always wants to debug eaddr */
		sreg->dbcr1 |= DBCR1_IAC1US | DBCR1_IAC2US |
		              DBCR1_IAC3US | DBCR1_IAC4US;
		sreg->dbcr2 |= DBCR2_DAC1US | DBCR2_DAC2US;
#endif
	}
}

int kvmppc_core_set_guest_debug(struct kvm_vcpu *vcpu,
                                struct kvm_guest_debug *dbg)
{
	if (!(dbg->control & KVM_GUESTDBG_ENABLE)) {
		vcpu->guest_debug = 0;
#ifdef CONFIG_KVM_BOOKE_HV
		/*
		 * When debug facilities are owned by guest then allow guest
		 * to write MSR.DE and default clear MSR_DE.
		 */
		mtspr(SPRN_MSRP, mfspr(SPRN_MSRP) & ~MSRP_DEP);
		isync();
		vcpu->arch.shared->msr &= ~MSR_DE;
#endif
		kvmppc_recalc_shadow_ac(vcpu);
		kvmppc_recalc_shadow_dbcr(vcpu);
		return 0;
	}

#ifdef CONFIG_KVM_BOOKE_HV
	/*
	 * When debug facilities are not owned by guest then do not allow
	 * guest to modify MSR.DE and default enable MSR_DE.
	 */
	mtspr(SPRN_MSRP, mfspr(SPRN_MSRP) | MSRP_DEP);
	isync();
	vcpu->arch.shared->msr |= MSR_DE;
#endif
	vcpu->guest_debug = dbg->control;
	vcpu->arch.shadow_dbg_reg.dbcr0 = 0;

	if (vcpu->guest_debug & KVM_GUESTDBG_SINGLESTEP)
		vcpu->arch.shadow_dbg_reg.dbcr0 |= DBCR0_IDM | DBCR0_IC;

	if (vcpu->guest_debug & KVM_GUESTDBG_USE_HW_BP) {
		struct kvmppc_debug_reg *gdbgr = &(vcpu->arch.shadow_dbg_reg);
		int n, b = 0, w = 0;
		const u32 bp_code[] = {
			DBCR0_IAC1 | DBCR0_IDM,
			DBCR0_IAC2 | DBCR0_IDM,
			DBCR0_IAC3 | DBCR0_IDM,
			DBCR0_IAC4 | DBCR0_IDM
		};
		const u32 wp_code[] = {
			DBCR0_DAC1W | DBCR0_IDM,
			DBCR0_DAC2W | DBCR0_IDM,
			DBCR0_DAC1R | DBCR0_IDM,
			DBCR0_DAC2R | DBCR0_IDM
		};

#ifndef CONFIG_KVM_BOOKE_HV
		gdbgr->dbcr1 = DBCR1_IAC1US | DBCR1_IAC2US |
		               DBCR1_IAC3US | DBCR1_IAC4US;
		gdbgr->dbcr2 = DBCR2_DAC1US | DBCR2_DAC2US;
#else
		gdbgr->dbcr1 = 0;
		gdbgr->dbcr2 = 0;
#endif

		for (n = 0; n < (BP_NUM + WP_NUM); n++) {
			u32 type = dbg->arch.bp[n].type;

			if (!type)
				break;

			if (type & (KVMPPC_DEBUG_WATCH_READ |
			            KVMPPC_DEBUG_WATCH_WRITE)) {
				if (w < WP_NUM) {
					if (type & KVMPPC_DEBUG_WATCH_READ)
						gdbgr->dbcr0 |= wp_code[w + 2];
					if (type & KVMPPC_DEBUG_WATCH_WRITE)
						gdbgr->dbcr0 |= wp_code[w];
					gdbgr->dac[w] = dbg->arch.bp[n].addr;
					w++;
				}
			} else if (type & KVMPPC_DEBUG_BREAKPOINT) {
				if (b < BP_NUM) {
					gdbgr->dbcr0 |= bp_code[b];
					gdbgr->iac[b] = dbg->arch.bp[n].addr;
					b++;
				}
			}
		}
	}

	return 0;
}

void kvmppc_clr_dbsr_bits(struct kvm_vcpu *vcpu, u32 dbsr_bits)
{
	if (vcpu->guest_debug == 0) {
		vcpu->arch.dbsr &= ~dbsr_bits;
		if (vcpu->arch.dbsr == 0)
			kvmppc_core_dequeue_debug(vcpu);
	}
}

#ifdef CONFIG_KVM_BOOKE206_PERFMON
void kvmppc_read_hwpmr(unsigned int pmr, u32 *val)
{
	switch (pmr) {
	case PMRN_PMC0:
		*val = mfpmr(PMRN_PMC0);
		break;
	case PMRN_PMC1:
		*val = mfpmr(PMRN_PMC1);
		break;
	case PMRN_PMC2:
		*val = mfpmr(PMRN_PMC2);
		break;
	case PMRN_PMC3:
		*val = mfpmr(PMRN_PMC3);
		break;
	case PMRN_PMLCA0:
		*val = mfpmr(PMRN_PMLCA0);
		break;
	case PMRN_PMLCA1:
		*val = mfpmr(PMRN_PMLCA1);
		break;
	case PMRN_PMLCA2:
		*val = mfpmr(PMRN_PMLCA2);
		break;
	case PMRN_PMLCA3:
		*val = mfpmr(PMRN_PMLCA3);
		break;
	case PMRN_PMLCB0:
		*val = mfpmr(PMRN_PMLCB0);
		break;
	case PMRN_PMLCB1:
		*val = mfpmr(PMRN_PMLCB1);
		break;
	case PMRN_PMLCB2:
		*val = mfpmr(PMRN_PMLCB2);
		break;
	case PMRN_PMLCB3:
		*val = mfpmr(PMRN_PMLCB3);
		break;
	case PMRN_PMGC0:
		*val = mfpmr(PMRN_PMGC0);
		break;
	default:
		pr_err("%s: mfpmr: unknown PMR %d\n", __func__, pmr);
	}
}

void kvmppc_write_hwpmr(unsigned int pmr, u32 val)
{
	switch (pmr) {
	case PMRN_PMC0:
		mtpmr(PMRN_PMC0, val);
		break;
	case PMRN_PMC1:
		mtpmr(PMRN_PMC1, val);
		break;
	case PMRN_PMC2:
		mtpmr(PMRN_PMC2, val);
		break;
	case PMRN_PMC3:
		mtpmr(PMRN_PMC3, val);
		break;
	case PMRN_PMLCA0:
		mtpmr(PMRN_PMLCA0, val);
		break;
	case PMRN_PMLCA1:
		mtpmr(PMRN_PMLCA1, val);
		break;
	case PMRN_PMLCA2:
		mtpmr(PMRN_PMLCA2, val);
		break;
	case PMRN_PMLCA3:
		mtpmr(PMRN_PMLCA3, val);
		break;
	case PMRN_PMLCB0:
		mtpmr(PMRN_PMLCB0, val);
		break;
	case PMRN_PMLCB1:
		mtpmr(PMRN_PMLCB1, val);
		break;
	case PMRN_PMLCB2:
		mtpmr(PMRN_PMLCB2, val);
		break;
	case PMRN_PMLCB3:
		mtpmr(PMRN_PMLCB3, val);
		break;
	case PMRN_PMGC0:
		mtpmr(PMRN_PMGC0, val);
		break;
	default:
		pr_err("%s: mtpmr: unknown PMR %d\n", __func__, pmr);
	}

	isync();
}

/* Check whether perfmon interrupt condition exists */
static bool kvmppc_perfmon_int_active(struct kvm_vcpu *vcpu)
{
	u32 pmr;
	int i;

	if (!(vcpu->arch.pm_reg.pmgc0 & PMGC0_PMIE))
		return false;

	for (i = 0; i < PERFMON_COUNTERS; i++) {
		/* If not enabled, can't be the cause of pending interrupt */
		kvmppc_read_hwpmr(PMRN_PMLCA0 + i, &pmr);
		if (!(pmr & PMLCA_CE))
			continue;

		/* If PMC.OV set, then interrupt handling is still pending */
		kvmppc_read_hwpmr(PMRN_PMC0 + i, &pmr);
		if (pmr & 0x80000000)
			return true;
	}
	return false;
}

void kvmppc_update_perfmon_ints(struct kvm_vcpu *vcpu)
{
	if (kvmppc_perfmon_int_active(vcpu)) {
		/* Enque if not already enqueued */
		if (!kvmppc_core_pending_perfmon(vcpu)) {
			kvmppc_core_queue_perfmon(vcpu);
#ifdef CONFIG_KVM_BOOKE_HV
			/*
			 * Do not allow PMR access and MSR.PMM update till
			 * perfmon interrupt condition is cleared by guest
			 * (PMIE cleared or OV cleared or CE cleared).
			 */
			mtspr(SPRN_MSRP, mfspr(SPRN_MSRP) | MSRP_PMMP);
			vcpu->arch.shadow_pm_reg.pmgc0 &= ~PMGC0_PMIE;
			vcpu->arch.shadow_pm_reg.pmgc0 |= PMGC0_FAC;
			mtpmr(PMRN_PMGC0, vcpu->arch.shadow_pm_reg.pmgc0);
#else
			mtpmr(PMRN_PMGC0, mfpmr(PMRN_PMGC0) & ~PMGC0_PMIE);
#endif
		}
	} else {
		/* Interrupt condition goes away, so clear interrupt */
		if (kvmppc_core_pending_perfmon(vcpu))
			kvmppc_core_dequeue_perfmon(vcpu);

#ifdef CONFIG_KVM_BOOKE_HV
			/* Allow Guest access to PMRs now */
			mtspr(SPRN_MSRP, mfspr(SPRN_MSRP) & ~MSRP_PMMP);
			vcpu->arch.shadow_pm_reg.pmgc0 = vcpu->arch.pm_reg.pmgc0;
#else
			mtpmr(PMRN_PMGC0, vcpu->arch.pm_reg.pmgc0);
#endif
	}
}

void kvmppc_set_hwpmlca(unsigned int idx, struct kvm_vcpu *vcpu)
{
	u32 reg;

	if (idx >= PERFMON_COUNTERS) {
		pr_err("%s: unknown PMLCA%d\n", __func__, idx);
		return;
	}

	reg = vcpu->arch.pm_reg.pmlca[idx];

#ifndef CONFIG_KVM_BOOKE_HV
	if ((reg & PMLCA_FCS) && !(vcpu->arch.shared->msr & MSR_PR))
		reg |= PMLCA_FC;
	if ((reg & PMLCA_FCU) && (vcpu->arch.shared->msr & MSR_PR))
		reg |= PMLCA_FC;
	if ((reg & PMLCA_FCM0) && !(vcpu->arch.shared->msr & MSR_PMM))
		reg |= PMLCA_FC;
	if ((reg & PMLCA_FCM1) && (vcpu->arch.shared->msr & MSR_PMM))
		reg |= PMLCA_FC;

	reg |= PMLCA_FCS;
#endif
	kvmppc_write_hwpmr(PMRN_PMLCA0 + idx, reg);
}

void kvmppc_set_hwpmlca_all(struct kvm_vcpu *vcpu)
{
	unsigned int i;
	for (i = 0; i < PERFMON_COUNTERS; i++)
		kvmppc_set_hwpmlca(i, vcpu);
}

void kvmppc_save_perfmon_regs(struct kvm_vcpu *vcpu)
{
#ifndef CONFIG_KVM_BOOKE_HV
	/* PMGC0 is saved at lightweight_exit for EHV */
	vcpu->arch.shadow_pm_reg.pmgc0 = mfpmr(PMRN_PMGC0);
#endif
	mtpmr(PMRN_PMGC0, PMGC0_FAC);
	isync();
	vcpu->arch.shadow_pm_reg.pmc[0] = mfpmr(PMRN_PMC0);
	vcpu->arch.shadow_pm_reg.pmc[1] = mfpmr(PMRN_PMC1);
	vcpu->arch.shadow_pm_reg.pmc[2] = mfpmr(PMRN_PMC2);
	vcpu->arch.shadow_pm_reg.pmc[3] = mfpmr(PMRN_PMC3);
	vcpu->arch.shadow_pm_reg.pmlca[0] = mfpmr(PMRN_PMLCA0);
	vcpu->arch.shadow_pm_reg.pmlca[1] = mfpmr(PMRN_PMLCA1);
	vcpu->arch.shadow_pm_reg.pmlca[2] = mfpmr(PMRN_PMLCA2);
	vcpu->arch.shadow_pm_reg.pmlca[3] = mfpmr(PMRN_PMLCA3);
#ifdef CONFIG_KVM_BOOKE_HV
	/* No need to save PMLCBx for no-EHV. They can be restored
	 * from guest PMCLBx.
	 */
	vcpu->arch.shadow_pm_reg.pmlcb[0] = mfpmr(PMRN_PMLCB0);
	vcpu->arch.shadow_pm_reg.pmlcb[1] = mfpmr(PMRN_PMLCB1);
	vcpu->arch.shadow_pm_reg.pmlcb[2] = mfpmr(PMRN_PMLCB2);
	vcpu->arch.shadow_pm_reg.pmlcb[3] = mfpmr(PMRN_PMLCB3);
#endif
}

void kvmppc_load_perfmon_regs(struct kvm_vcpu *vcpu)
{

#ifdef CONFIG_KVM_BOOKE_HV
	/* Do not rely on PMGC0 state, so freeze all counters
	 * and disable interrupt now. Actual PMGC0 will be
	 * loaded at lightweight_exit.
	 */
	mtpmr(PMRN_PMGC0, PMGC0_FAC);
	isync();
	mtpmr(PMRN_PMLCB0, vcpu->arch.shadow_pm_reg.pmlcb[0]);
	mtpmr(PMRN_PMLCB1, vcpu->arch.shadow_pm_reg.pmlcb[1]);
	mtpmr(PMRN_PMLCB2, vcpu->arch.shadow_pm_reg.pmlcb[2]);
	mtpmr(PMRN_PMLCB3, vcpu->arch.shadow_pm_reg.pmlcb[3]);
#else
	mtpmr(PMRN_PMGC0, vcpu->arch.shadow_pm_reg.pmgc0);
	isync();
	mtpmr(PMRN_PMLCB0, vcpu->arch.pm_reg.pmlcb[0]);
	mtpmr(PMRN_PMLCB1, vcpu->arch.pm_reg.pmlcb[1]);
	mtpmr(PMRN_PMLCB2, vcpu->arch.pm_reg.pmlcb[2]);
	mtpmr(PMRN_PMLCB3, vcpu->arch.pm_reg.pmlcb[3]);
#endif
	mtpmr(PMRN_PMC0, vcpu->arch.shadow_pm_reg.pmc[0]);
	mtpmr(PMRN_PMC1, vcpu->arch.shadow_pm_reg.pmc[1]);
	mtpmr(PMRN_PMC2, vcpu->arch.shadow_pm_reg.pmc[2]);
	mtpmr(PMRN_PMC3, vcpu->arch.shadow_pm_reg.pmc[3]);
	mtpmr(PMRN_PMLCA0, vcpu->arch.shadow_pm_reg.pmlca[0]);
	mtpmr(PMRN_PMLCA1, vcpu->arch.shadow_pm_reg.pmlca[1]);
	mtpmr(PMRN_PMLCA2, vcpu->arch.shadow_pm_reg.pmlca[2]);
	mtpmr(PMRN_PMLCA3, vcpu->arch.shadow_pm_reg.pmlca[3]);
	isync();
}
#endif /* CONFIG_KVM_BOOKE206_PERFMON */

/*
 * We install our own exception handlers by hijacking IVPR.
 * IVPR must be 16-bit aligned.
 */
static char kvmppc_booke_vector[PAGE_SIZE * 2]
		__attribute__ ((aligned(1 << 16)));
unsigned long kvmppc_booke_handlers = (unsigned long)kvmppc_booke_vector;

int __init kvmppc_booke_init(void)
{
#ifndef CONFIG_KVM_BOOKE_HV
	unsigned long ivor[16];
	unsigned long *handler = kvmppc_booke_handler_addr;
	unsigned long max_ivor = 0;
	int i;

	/* XXX make sure our handlers are smaller than Linux's */

	/* Copy our interrupt handlers to match host IVORs. That way we don't
	 * have to swap the IVORs on every guest/host transition. */
	ivor[0] = mfspr(SPRN_IVOR0);
	ivor[1] = mfspr(SPRN_IVOR1);
	ivor[2] = mfspr(SPRN_IVOR2);
	ivor[3] = mfspr(SPRN_IVOR3);
	ivor[4] = mfspr(SPRN_IVOR4);
	ivor[5] = mfspr(SPRN_IVOR5);
	ivor[6] = mfspr(SPRN_IVOR6);
	ivor[7] = mfspr(SPRN_IVOR7);
	ivor[8] = mfspr(SPRN_IVOR8);
	ivor[9] = mfspr(SPRN_IVOR9);
	ivor[10] = mfspr(SPRN_IVOR10);
	ivor[11] = mfspr(SPRN_IVOR11);
	ivor[12] = mfspr(SPRN_IVOR12);
	ivor[13] = mfspr(SPRN_IVOR13);
	ivor[14] = mfspr(SPRN_IVOR14);
	ivor[15] = mfspr(SPRN_IVOR15);

	for (i = 0; i < 16; i++) {
		if (ivor[i] > max_ivor)
			max_ivor = i;

		memcpy((void *)kvmppc_booke_handlers + ivor[i],
		       (void *)handler[i], handler[i + 1] - handler[i]);
	}

	flush_icache_range(kvmppc_booke_handlers,
	                   kvmppc_booke_handlers + ivor[max_ivor] +
                               handler[max_ivor + 1] - handler[max_ivor]);
#endif /* !BOOKE_HV */
	return 0;
}

void __exit kvmppc_booke_exit(void)
{
	kvm_exit();
}
