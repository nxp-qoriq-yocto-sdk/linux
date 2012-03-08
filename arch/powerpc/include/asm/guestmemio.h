/* @file
 * Load/store acccesors to guest virtual addresses.
 */
/* Copyright (C) 2007-2010 Freescale Semiconductor, Inc.
 * Author: Scott Wood <scottwood@freescale.com>
 * Adapted for Linux by Ashish Kalra <ashish.kalra@freescale.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */

#ifndef __GUESTMEMIO_H_
#define __GUESTMEMIO_H_

#include <asm/kvm_e500mc.h>
#include <asm/reg_booke.h>

#define GUESTMEM_OK 0
#define GUESTMEM_TLBMISS 1
#define GUESTMEM_TLBERR 2

/* function to synchronize a cache block in guest memory
 * when modifying instructions.  This follows the recommended sequence
 *  in the EREF for self modifying code.
 */
static inline int guestmem_icache_block_sync(char *ptr)
{
	register int stat asm("r3") = GUESTMEM_OK;

	asm volatile("1: dcbfep %y1;"
	    "2: msync;"
	    "3: icbiep %y1;"
	    "4: msync;"
	    "isync;"
	    ".section __ex_table,\"a\";"
	    ".long 1b;"
	    ".long 2b;"
	    ".long 3b;"
	    ".long 4b;"
	    ".previous;" : "+r" (stat) : "Z" (*ptr) : "memory");

	return stat;
}

/* The relevent guestmem_set() call must be made prior
 * to executing any guestmem_in() calls.  It is not
 * required for guestmem_out().
 */
static inline void guestmem_set_data(struct kvm_vcpu *vcpu)
{
	uint32_t eplc = mfspr(SPRN_EPLC);
	uint32_t new_eplc = eplc;
	struct kvm_vcpu_arch *vcpu_arch = &vcpu->arch;
	struct kvmppc_vcpu_e500mc *vcpu_e500mc = to_e500mc(vcpu);

	new_eplc &= ~EPC_EAS;
	new_eplc |= (vcpu_arch->shared->msr << (63 - MSR_DR_LG - EPCBIT_EAS)) &
			EPC_EAS;
	new_eplc |= (vcpu_arch->shadow_pid << EPC_EPID_SHIFT) & EPC_EPID;
	new_eplc |= (vcpu_e500mc->lpid << EPC_ELPID_SHIFT) & EPC_ELPID;
	new_eplc |= (vcpu_arch->shared->msr << (63 - MSR_PR_LG - EPCBIT_EPR)) &
			 EPC_EPR;
	new_eplc |= EPC_EGS; /* Always guest access */

	if (eplc != new_eplc) {
		mtspr(SPRN_EPLC, new_eplc);
		isync();
	}
}

static inline void guestmem_set_insn(struct kvm_vcpu *vcpu)
{
	uint32_t eplc = mfspr(SPRN_EPLC);
	uint32_t new_eplc = eplc;
	struct kvm_vcpu_arch *vcpu_arch = &vcpu->arch;
	struct kvmppc_vcpu_e500mc *vcpu_e500mc = to_e500mc(vcpu);

	new_eplc &= ~EPC_EAS;
	new_eplc |= (vcpu_arch->shared->msr << (63 - MSR_IR_LG - EPCBIT_EAS)) &
			 EPC_EAS;
	new_eplc |= (vcpu_arch->shadow_pid << EPC_EPID_SHIFT) & EPC_EPID;
	new_eplc |= (vcpu_e500mc->lpid << EPC_ELPID_SHIFT) & EPC_ELPID;
	new_eplc |= (vcpu_arch->shared->msr << (63 - MSR_PR_LG - EPCBIT_EPR)) &
			 EPC_EPR;
	new_eplc |= EPC_EGS; /* Always guest access */

	if (eplc != new_eplc) {
		mtspr(SPRN_EPLC, new_eplc);
		isync();
	}
}


static inline int guestmem_in32(uint32_t *ptr, uint32_t *val)
{
	register int stat asm("r3") = GUESTMEM_OK;

	asm("1: lwepx %0, %y2;"
	    "2:"
	    ".section __ex_table,\"a\";"
	    ".long 1b;"
	    ".long 2b;"
	    ".previous;" : "=r" (*val), "+r" (stat) : "Z" (*ptr));

	return stat;
}

static inline int guestmem_in8(uint8_t *ptr, uint8_t *val)
{
	register int stat asm("r3") = GUESTMEM_OK;

	asm("1: lbepx %0, %y2;"
	    "2:"
	    ".section __ex_table,\"a\";"
	    ".long 1b;"
	    ".long 2b;"
	    ".previous;" : "=r" (*val), "+r" (stat) : "Z" (*ptr));

	return stat;
}

static inline int guestmem_out32(uint32_t *ptr, uint32_t val)
{
	register int stat asm("r3") = GUESTMEM_OK;

	asm("1: stwepx %2, %y1;"
	    "2:"
	    ".section __ex_table,\"a\";"
	    ".long 1b;"
	    ".long 2b;"
	    ".previous;" : "+r" (stat), "=Z" (*ptr) : "r" (val));

	return stat;
}

static inline int guestmem_out8(uint8_t *ptr, uint8_t val)
{
	register int stat asm("r3") = GUESTMEM_OK;

	asm("1: stbepx %2, %y1;"
	    "2:"
	    ".section __ex_table,\"a\";"
	    ".long 1b;"
	    ".long 2b;"
	    ".previous;" : "+r" (stat), "=Z" (*ptr) : "r" (val));

	return stat;
}

#endif /* __GUESTMEMIO_H_ */
