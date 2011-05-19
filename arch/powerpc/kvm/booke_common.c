/*
 * Code common to booke and bookehv
 *
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
 * Copyright (C) 2011 Freescale Semiconductor, Inc.
 */

#include <linux/kvm_host.h>
#include "booke.h"

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
 * longer than the kernel timer API supports, we return ULONG_MAX instead.
 */
static unsigned long wdt_next_timeout(struct kvm_vcpu *vcpu)
{
	unsigned long long tb, mask, nr_jiffies = 0;

	mask = 1ULL << (63 - vcpu->arch.wdt_period);
	tb = get_tb();
	if (tb & mask)
		nr_jiffies += mask;

	nr_jiffies += mask - (tb & (mask - 1));

	if (do_div(nr_jiffies, tb_ticks_per_jiffy))
		nr_jiffies++;

	return min_t(unsigned long long, nr_jiffies, MAX_TIMEOUT);
}

static void kvmppc_emulate_wdt(struct kvm_vcpu *vcpu)
{
	unsigned long nr_jiffies;

	vcpu->arch.wdt_period = TCR_GET_FSL_WP(vcpu->arch.tcr);

	nr_jiffies = wdt_next_timeout(vcpu);
	if (nr_jiffies < MAX_TIMEOUT)
		mod_timer(&vcpu->arch.wdt_timer, jiffies + nr_jiffies);
	else
		del_timer(&vcpu->arch.wdt_timer);
}

void kvmppc_wdt_pause(struct kvm_vcpu *vcpu)
{
	del_timer(&vcpu->arch.wdt_timer);
}

void kvmppc_wdt_resume(struct kvm_vcpu *vcpu)
{
	unsigned long nr_jiffies;

	nr_jiffies = wdt_next_timeout(vcpu);
	if (nr_jiffies < MAX_TIMEOUT)
		mod_timer(&vcpu->arch.wdt_timer, jiffies + nr_jiffies);
	else
		del_timer(&vcpu->arch.wdt_timer);
}

void kvmppc_set_tcr(struct kvm_vcpu *vcpu, u32 new_tcr)
{
	vcpu->arch.tcr = new_tcr;
	smp_wmb();

	kvmppc_emulate_wdt(vcpu);

	/*
	 * Since TCR changed, we need to check
	 * if blocked interrupts are deliverable.
	 */
	if ((new_tcr & TCR_DIE) && (vcpu->arch.tsr & TSR_DIS)) {
		kvmppc_core_queue_dec(vcpu);
		kvmppc_wakeup_vcpu(vcpu);
	}
	if ((new_tcr & TCR_WIE) && (vcpu->arch.tsr & TSR_WIS)) {
		kvmppc_core_queue_watchdog(vcpu);
		kvmppc_wakeup_vcpu(vcpu);
	}
}

void kvmppc_set_tsr_bits(struct kvm_vcpu *vcpu, u32 tsr_bits)
{
	set_bits(tsr_bits, &vcpu->arch.tsr);
	smp_wmb();

	if ((tsr_bits & TSR_DIS) && (vcpu->arch.tcr & TCR_DIE)) {
		kvmppc_core_queue_dec(vcpu);
		kvmppc_wakeup_vcpu(vcpu);
	}
	if ((tsr_bits & TSR_WIS) && (vcpu->arch.tcr & TCR_WIE)) {
		kvmppc_core_queue_watchdog(vcpu);
		kvmppc_wakeup_vcpu(vcpu);
	}
}

void kvmppc_clr_tsr_bits(struct kvm_vcpu *vcpu, u32 tsr_bits)
{
	if (tsr_bits & TSR_DIS)
		kvmppc_core_dequeue_dec(vcpu);
	if (tsr_bits & TSR_WIS)
		kvmppc_core_dequeue_watchdog(vcpu);

	smp_wmb();
	clear_bits(tsr_bits, &vcpu->arch.tsr);
}

void kvmppc_watchdog_func(unsigned long data)
{
	struct kvm_vcpu *vcpu = (struct kvm_vcpu *)data;
	unsigned long nr_jiffies;
	u32 tsr = vcpu->arch.tsr;

	/* Time out event */
	if (tsr & TSR_ENW) {
		if (tsr & TSR_WIS) {
			/* watchdog reset control */
			if (vcpu->arch.tcr & TCR_WRC_MASK) {
				vcpu->arch.wdt_want_action = true;
				kvmppc_wakeup_vcpu(vcpu);
			}
			kvmppc_clr_tsr_bits(vcpu, TCR_WRC_MASK);
			kvmppc_set_tsr_bits(vcpu, vcpu->arch.tcr & TCR_WRC_MASK);
		} else {
			kvmppc_set_tsr_bits(vcpu, TSR_WIS);
		}
	} else {
		kvmppc_set_tsr_bits(vcpu, TSR_ENW);
	}

	nr_jiffies = wdt_next_timeout(vcpu);
	if (nr_jiffies < MAX_TIMEOUT)
		mod_timer(&vcpu->arch.wdt_timer, jiffies + nr_jiffies);
	else
		del_timer(&vcpu->arch.wdt_timer);
}

void kvmppc_decrementer_func(unsigned long data)
{
	struct kvm_vcpu *vcpu = (struct kvm_vcpu *)data;

	kvmppc_set_tsr_bits(vcpu, TSR_DIS);
}

#ifdef CONFIG_KVM_E500
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

void kvmppc_clear_pending_perfmon(struct kvm_vcpu *vcpu)
{
	u32 pmr;
	int i;

	for (i = 0; i < PERFMON_COUNTERS; i++) {
		/* If not enabled, can't be the cause of pending interrupt */
		kvmppc_read_hwpmr(PMRN_PMLCA0 + i, &pmr);
		if (!(pmr & PMLCA_CE))
			continue;

		/* If PMC.OV set, then interrupt handling is still pending */
		kvmppc_read_hwpmr(PMRN_PMC0 + i, &pmr);
		if (pmr & 0x80000000)
			return;
	}
	kvmppc_core_dequeue_perfmon(vcpu);
	mtpmr(PMRN_PMGC0, vcpu->arch.pm_reg.pmgc0);
	isync();
}

void kvmppc_set_hwpmlca(unsigned int idx, struct kvm_vcpu *vcpu)
{
	u32 reg;

	if (idx >= PERFMON_COUNTERS) {
		pr_err("%s: unknown PMLCA%d\n", __func__, idx);
		return;
	}

	reg = vcpu->arch.pm_reg.pmlca[idx];

	if ((reg & PMLCA_FCS) && !(vcpu->arch.shared->msr & MSR_PR))
		reg |= PMLCA_FC;
	if ((reg & PMLCA_FCU) && (vcpu->arch.shared->msr & MSR_PR))
		reg |= PMLCA_FC;
	if ((reg & PMLCA_FCM0) && !(vcpu->arch.shared->msr & MSR_PMM))
		reg |= PMLCA_FC;
	if ((reg & PMLCA_FCM1) && (vcpu->arch.shared->msr & MSR_PMM))
		reg |= PMLCA_FC;

	reg |= PMLCA_FCS;
	kvmppc_write_hwpmr(PMRN_PMLCA0 + idx, reg);
}

void kvmppc_set_hwpmlca_all(struct kvm_vcpu *vcpu)
{
	unsigned int i;
	for (i = 0; i < PERFMON_COUNTERS; i++)
		kvmppc_set_hwpmlca(i, vcpu);
}
#endif /* CONFIG_KVM_E500 */

void kvmppc_set_dbsr_bits(struct kvm_vcpu *vcpu, u32 dbsr_bits)
{
	vcpu->arch.dbsr |= dbsr_bits;
	if (vcpu->arch.dbsr != 0)
		kvmppc_core_queue_debug(vcpu);
}

void kvmppc_clr_dbsr_bits(struct kvm_vcpu *vcpu, u32 dbsr_bits)
{
	vcpu->arch.dbsr &= ~dbsr_bits;
	if (vcpu->arch.dbsr == 0)
		kvmppc_core_dequeue_debug(vcpu);
}
