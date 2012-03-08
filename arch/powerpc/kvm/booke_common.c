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
	kvmppc_emulate_wdt(vcpu);

	/*
	 * Since TCR changed, we need to check
	 * if blocked interrupts are deliverable.
	 */
	kvmppc_wakeup_vcpu(vcpu);
}

void kvmppc_set_tsr_bits(struct kvm_vcpu *vcpu, u32 tsr_bits)
{
	set_bits(tsr_bits, &vcpu->arch.tsr);

	if (tsr_bits & TSR_DIS) {
		kvmppc_core_queue_dec(vcpu);
		kvmppc_wakeup_vcpu(vcpu);
	}
	if (tsr_bits & TSR_WIS) {
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
