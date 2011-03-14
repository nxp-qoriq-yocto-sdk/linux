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

void kvmppc_set_tcr(struct kvm_vcpu *vcpu, u32 new_tcr)
{
	vcpu->arch.tcr = new_tcr;

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
}

void kvmppc_clr_tsr_bits(struct kvm_vcpu *vcpu, u32 tsr_bits)
{
	if (tsr_bits & TSR_DIS)
		kvmppc_core_dequeue_dec(vcpu);

	clear_bits(tsr_bits, &vcpu->arch.tsr);
}

void kvmppc_decrementer_func(unsigned long data)
{
	struct kvm_vcpu *vcpu = (struct kvm_vcpu *)data;

	kvmppc_set_tsr_bits(vcpu, TSR_DIS);
}
