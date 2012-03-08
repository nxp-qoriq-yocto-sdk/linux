/*
 * Copyright (C) 2010-2011 Freescale Semiconductor, Inc. All rights reserved.
 *
 * Author: Ashish Kalra, ashish.kalra@freescale.com
 *         Varun Sethi, varun.sethi@freescale.com
 *
 * Description:
 * This file is based on arch/powerpc/kvm/e500_tlb.c,
 * by Yu Liu <yu.liu@freescale.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2, as
 * published by the Free Software Foundation.
 */

#include <linux/types.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <linux/highmem.h>
#include <asm/kvm_ppc.h>
#include <asm/kvm_e500mc.h>

#include "../mm/mmu_decl.h"
#include "e500mc_tlb.h"
#include "trace.h"

#define to_htlb1_esel(esel) (tlb1_entry_num - (esel) - 1)

static unsigned int tlb1_entry_num;

void kvmppc_dump_tlbs(struct kvm_vcpu *vcpu)
{
	struct kvmppc_vcpu_e500mc *vcpu_e500mc = to_e500mc(vcpu);
	struct tlbe *tlbe;
	int i, tlbsel;

	printk("| %8s | %8s | %8s | %8s | %8s |\n",
			"nr", "mas1", "mas2", "mas3", "mas7");

	for (tlbsel = 0; tlbsel < 2; tlbsel++) {
		printk("Guest TLB%d:\n", tlbsel);
		for (i = 0; i < vcpu_e500mc->guest_tlb_size[tlbsel]; i++) {
			tlbe = &vcpu_e500mc->guest_tlb[tlbsel][i];
			if (tlbe->mas1 & MAS1_VALID)
				printk(" G[%d][%3d] |  %08X | %08X | %08X | %08X |\n",
					tlbsel, i, tlbe->mas1, tlbe->mas2,
					tlbe->mas3, tlbe->mas7);
		}
	}

	for (tlbsel = 0; tlbsel < 2; tlbsel++) {
		printk("Shadow TLB%d:\n", tlbsel);
		for (i = 0; i < vcpu_e500mc->shadow_tlb_size[tlbsel]; i++) {
			tlbe = &vcpu_e500mc->shadow_tlb[tlbsel][i];
			if (tlbe->mas1 & MAS1_VALID)
				printk(" S[%d][%3d] |  %08X | %08X | %08X | %08X |\n",
					tlbsel, i, tlbe->mas1, tlbe->mas2,
					tlbe->mas3, tlbe->mas7);
		}
	}
}

/* Search the guest TLB for a matching entry. */
static int kvmppc_e500mc_tlb_index(struct kvmppc_vcpu_e500mc *vcpu_e500mc,
		gva_t eaddr, int tlbsel, unsigned int pid, int as,
		unsigned int lpid)
{
	int i;

	/* XXX Replace loop with fancy data structures. */
	for (i = 0; i < vcpu_e500mc->guest_tlb_size[tlbsel]; i++) {
		struct tlbe *tlbe = &vcpu_e500mc->guest_tlb[tlbsel][i];
		unsigned int tid, tlpid;

		if (eaddr < get_tlb_eaddr(tlbe))
			continue;

		if (eaddr > get_tlb_end(tlbe))
			continue;

		tid = get_tlb_tid(tlbe);
		if (tid && (tid != pid))
			continue;

		if (!get_tlb_v(tlbe))
			continue;

		if (get_tlb_ts(tlbe) != as && as != -1)
			continue;

		tlpid = get_tlb_lpid(tlbe);
		if (tlpid && (tlpid != lpid))
			continue;

		return i;
	}

	return -1;
}

int kvmppc_e500mc_tlb_search(struct kvm_vcpu *vcpu, gva_t eaddr,
				 unsigned int pid, int as,
				 unsigned int lpid)
{
	struct kvmppc_vcpu_e500mc *vcpu_e500mc = to_e500mc(vcpu);
	int esel, tlbsel;

	for (tlbsel = 0; tlbsel < 2; tlbsel++) {
		esel = kvmppc_e500mc_tlb_index(vcpu_e500mc, eaddr, tlbsel, pid, as, lpid);
		if (esel >= 0)
			return index_of(tlbsel, esel);
	}

	return -1;
}

static inline unsigned int tlb0_get_next_victim(
		struct kvmppc_vcpu_e500mc *vcpu_e500mc)
{
	unsigned int victim;

	victim = vcpu_e500mc->guest_tlb_nv[0]++;
	if (unlikely(vcpu_e500mc->guest_tlb_nv[0] >= KVM_E500MC_TLB0_WAY_NUM))
		vcpu_e500mc->guest_tlb_nv[0] = 0;

	return victim;
}

static inline unsigned int tlb1_max_shadow_size(void)
{
	return tlb1_entry_num - tlbcam_index;
}

static inline int tlbe_is_writable(struct tlbe *tlbe)
{
	return tlbe->mas3 & (MAS3_SW|MAS3_UW);
}

static inline u32 e500mc_shadow_mas3_attrib(u32 mas3, int usermode)
{
	/* Mask off reserved bits. */
	mas3 &= MAS3_ATTRIB_MASK;
	return mas3;
}

static inline u32 e500mc_shadow_mas2_attrib(u32 mas2, int usermode)
{
#ifdef CONFIG_SMP
	return (mas2 & MAS2_ATTRIB_MASK) | MAS2_M;
#else
	return mas2 & MAS2_ATTRIB_MASK;
#endif
}

/*
 * writing shadow tlb entry to host TLB
 */
static inline void __write_host_tlbe(unsigned register mas0, struct tlbe *stlbe)
{
	local_irq_disable();

	mtspr(SPRN_MAS0, mas0);
	mtspr(SPRN_MAS1, stlbe->mas1);
	mtspr(SPRN_MAS2, stlbe->mas2);
	mtspr(SPRN_MAS3, stlbe->mas3);
	mtspr(SPRN_MAS7, stlbe->mas7);
	mtspr(SPRN_MAS8, stlbe->mas8);
	asm volatile("isync; tlbwe" : : : "memory");

	/* Must clear mas8 for other host tlbwe's */
	mtspr(SPRN_MAS8, 0);

	local_irq_enable();
}

static inline void write_host_tlbe(struct kvmppc_vcpu_e500mc *vcpu_e500mc,
		int tlbsel, int esel)
{
	struct tlbe *stlbe = &vcpu_e500mc->shadow_tlb[tlbsel][esel];

	if (tlbsel == 0) {
		__write_host_tlbe((MAS0_TLBSEL(0) | MAS0_ESEL(esel)), stlbe);
	} else {
		__write_host_tlbe((MAS0_TLBSEL(1) |
				MAS0_ESEL(to_htlb1_esel(esel))), stlbe);
	}
}

void kvmppc_e500mc_tlb_load(struct kvm_vcpu *vcpu, int cpu)
{
	struct kvmppc_vcpu_e500mc *vcpu_e500mc = to_e500mc(vcpu);

	if (vcpu_e500mc->oldpir != mfspr(SPRN_PIR)) {
		mtspr(SPRN_MAS5, 0x80000000 | (vcpu_e500mc->lpid & 0xFF));
		asm volatile("tlbilxlpid");
		mtspr(SPRN_MAS5, 0);
	}

	/* TBD: Reload the hardware tlb from shadow tlb */
}

void kvmppc_e500mc_tlb_put(struct kvm_vcpu *vcpu)
{
	struct kvmppc_vcpu_e500mc *vcpu_e500mc = to_e500mc(vcpu);

	vcpu_e500mc->oldpir = mfspr(SPRN_PIR);

}

static void kvmppc_e500mc_shadow_release(struct kvmppc_vcpu_e500mc *vcpu_e500mc,
		int tlbsel, int esel)
{
	struct tlbe *stlbe = &vcpu_e500mc->shadow_tlb[tlbsel][esel];
	struct page *page = vcpu_e500mc->shadow_pages[tlbsel][esel];

	if (page) {
		vcpu_e500mc->shadow_pages[tlbsel][esel] = NULL;

		if (get_tlb_v(stlbe)) {
			if (tlbe_is_writable(stlbe))
				kvm_release_page_dirty(page);
			else
				kvm_release_page_clean(page);
		}
	}
}

static void kvmppc_e500mc_stlbe_invalidate(
		struct kvmppc_vcpu_e500mc *vcpu_e500mc,
		int tlbsel, int esel)
{
	struct tlbe *stlbe = &vcpu_e500mc->shadow_tlb[tlbsel][esel];

	kvmppc_e500mc_shadow_release(vcpu_e500mc, tlbsel, esel);
	stlbe->mas1 = 0;
	write_host_tlbe(vcpu_e500mc, tlbsel, esel);
	trace_kvm_stlb_inval(index_of(tlbsel, esel));
}

static void kvmppc_e500mc_tlb1_invalidate(
		struct kvmppc_vcpu_e500mc *vcpu_e500mc,
		gva_t eaddr, gva_t eend, u32 tid, u32 lpid)
{
	unsigned int pid = tid & 0xff;
	unsigned int i;

	/* XXX Replace loop with fancy data structures. */
	for (i = 0; i < vcpu_e500mc->guest_tlb_size[1]; i++) {
		struct tlbe *stlbe = &vcpu_e500mc->shadow_tlb[1][i];
		unsigned int tlpid;

		if (!get_tlb_v(stlbe))
			continue;

		if (eend < get_tlb_eaddr(stlbe))
			continue;

		if (eaddr > get_tlb_end(stlbe))
			continue;

		tid = get_tlb_tid(stlbe);
		if (tid && (tid != pid))
			continue;

		tlpid = get_tlb_lpid(stlbe);
		if (tlpid && (tlpid != lpid))
			continue;

		kvmppc_e500mc_stlbe_invalidate(vcpu_e500mc, 1, i);
	}
}

static inline void kvmppc_e500mc_deliver_tlb_miss(struct kvm_vcpu *vcpu,
		unsigned int eaddr, int as)
{
	struct kvmppc_vcpu_e500mc *vcpu_e500mc = to_e500mc(vcpu);
	unsigned int victim, pidsel, tsized;
	int tlbsel;

	/* since we only have two TLBs, only lower bit is used. */
	tlbsel = (vcpu->arch.shared->mas4 >> 28) & 0x1;
	victim = (tlbsel == 0) ? tlb0_get_next_victim(vcpu_e500mc) : 0;
	pidsel = (vcpu->arch.shared->mas4 >> 16) & 0xf;
	tsized = (vcpu->arch.shared->mas4 >> 7) & 0x1f;

	vcpu->arch.shared->mas0 = MAS0_TLBSEL(tlbsel) | MAS0_ESEL(victim)
		| MAS0_NV(vcpu_e500mc->guest_tlb_nv[tlbsel]);
	vcpu->arch.shared->mas1 = MAS1_VALID | (as ? MAS1_TS : 0)
		| MAS1_TID(vcpu->arch.shadow_pid)
		| MAS1_TSIZE(tsized);
	vcpu->arch.shared->mas2 = (eaddr & MAS2_EPN)
		| (vcpu->arch.shared->mas4 & MAS2_ATTRIB_MASK);
	vcpu->arch.shared->mas7_3 &= MAS3_U0 | MAS3_U1 | MAS3_U2 | MAS3_U3;
	vcpu->arch.shared->mas6 = (vcpu->arch.shared->mas6 & MAS6_SPID1)
		| (get_cur_pid(vcpu) << 16)
		| (as ? MAS6_SAS : 0);
}

static inline void kvmppc_e500mc_shadow_map(
	struct kvmppc_vcpu_e500mc *vcpu_e500mc,
	u64 gvaddr, gfn_t gfn, struct tlbe *gtlbe, int tlbsel, int esel)
{
	struct page *new_page;
	struct tlbe *stlbe;
	hpa_t hpaddr;

	stlbe = &vcpu_e500mc->shadow_tlb[tlbsel][esel];

	/* Get reference to new page. */
	new_page = gfn_to_page(vcpu_e500mc->vcpu.kvm, gfn);
	if (is_error_page(new_page)) {
		printk(KERN_ERR "Couldn't get guest page for gfn %lx!\n",
				(long)gfn);
		kvm_release_page_clean(new_page);
		return;
	}
	hpaddr = page_to_phys(new_page);

	/* Drop reference to old page. */
	kvmppc_e500mc_shadow_release(vcpu_e500mc, tlbsel, esel);

	vcpu_e500mc->shadow_pages[tlbsel][esel] = new_page;

	/* Force GS=1 IPROT=0 TSIZE=4KB for all guest mappings. */
	stlbe->mas1 = MAS1_TSIZE(BOOK3E_PAGESZ_4K)
		| MAS1_TID(get_tlb_tid(gtlbe)) | (gtlbe->mas1 & MAS1_TS) | MAS1_VALID;
	stlbe->mas2 = (gvaddr & MAS2_EPN)
		| e500mc_shadow_mas2_attrib(gtlbe->mas2,
				vcpu_e500mc->vcpu.arch.shared->msr & MSR_PR);
	stlbe->mas3 = (hpaddr & MAS3_RPN)
		| e500mc_shadow_mas3_attrib(gtlbe->mas3,
				vcpu_e500mc->vcpu.arch.shared->msr & MSR_PR);
	stlbe->mas7 = (hpaddr >> 32) & MAS7_RPN;
	stlbe->mas8 = MAS8_TGS | vcpu_e500mc->lpid;

	trace_kvm_stlb_write(index_of(tlbsel, esel), stlbe->mas1, stlbe->mas2,
			     stlbe->mas3, stlbe->mas7);
}

/* XXX only map the one-one case, for now use TLB0 */
static int kvmppc_e500mc_stlbe_map(struct kvmppc_vcpu_e500mc *vcpu_e500mc,
		int tlbsel, int esel)
{
	struct tlbe *gtlbe;

	gtlbe = &vcpu_e500mc->guest_tlb[tlbsel][esel];

	kvmppc_e500mc_shadow_map(vcpu_e500mc, get_tlb_eaddr(gtlbe),
			get_tlb_raddr(gtlbe) >> PAGE_SHIFT,
			gtlbe, tlbsel, esel);

	return esel;
}

/* Caller must ensure that the specified guest TLB entry is safe to insert into
 * the shadow TLB. */
/* XXX for both one-one and one-to-many , for now use TLB1 */
static int kvmppc_e500mc_tlb1_map(struct kvmppc_vcpu_e500mc *vcpu_e500mc,
		u64 gvaddr, gfn_t gfn, struct tlbe *gtlbe)
{
	unsigned int victim;

	victim = vcpu_e500mc->guest_tlb_nv[1]++;

	if (unlikely(vcpu_e500mc->guest_tlb_nv[1] >= tlb1_max_shadow_size()))
		vcpu_e500mc->guest_tlb_nv[1] = 0;

	kvmppc_e500mc_shadow_map(vcpu_e500mc, gvaddr, gfn, gtlbe, 1, victim);

	return victim;
}

static int kvmppc_e500mc_gtlbe_invalidate(
		struct kvmppc_vcpu_e500mc *vcpu_e500mc,
		int tlbsel, int esel)
{
	struct tlbe *gtlbe = &vcpu_e500mc->guest_tlb[tlbsel][esel];

	if (unlikely(get_tlb_iprot(gtlbe)))
		return -1;

	if (tlbsel == 1) {
		kvmppc_e500mc_tlb1_invalidate(vcpu_e500mc,
				get_tlb_eaddr(gtlbe),
				get_tlb_end(gtlbe),
				get_tlb_tid(gtlbe),
				vcpu_e500mc->lpid);
	} else {
		kvmppc_e500mc_stlbe_invalidate(vcpu_e500mc, tlbsel, esel);
	}

	gtlbe->mas1 = 0;

	return 0;
}

int kvmppc_e500mc_emul_mt_mmucsr0(
	struct kvmppc_vcpu_e500mc *vcpu_e500mc, ulong value)
{
	int esel;

	if (value & MMUCSR0_TLB0FI)
		for (esel = 0; esel < vcpu_e500mc->guest_tlb_size[0]; esel++)
			kvmppc_e500mc_gtlbe_invalidate(vcpu_e500mc, 0, esel);
	if (value & MMUCSR0_TLB1FI)
		for (esel = 0; esel < vcpu_e500mc->guest_tlb_size[1]; esel++)
			kvmppc_e500mc_gtlbe_invalidate(vcpu_e500mc, 1, esel);

	/* TBD: Support for partitioned invalidations */
	_tlbil_all();

	return EMULATE_DONE;
}

int kvmppc_e500mc_emul_tlbivax(struct kvm_vcpu *vcpu, int ra, int rb)
{
	struct kvmppc_vcpu_e500mc *vcpu_e500mc = to_e500mc(vcpu);
	unsigned int ia;
	int esel, tlbsel;
	gva_t ea;

	ea = ((ra) ? kvmppc_get_gpr(vcpu, ra) : 0) + kvmppc_get_gpr(vcpu, rb);

	ia = (ea >> 2) & 0x1;

	/* since we only have two TLBs, only lower bit is used. */
	tlbsel = (ea >> 3) & 0x1;

	if (ia) {
		/* invalidate all entries */
		for (esel = 0; esel < vcpu_e500mc->guest_tlb_size[tlbsel]; esel++)
			kvmppc_e500mc_gtlbe_invalidate(vcpu_e500mc, tlbsel, esel);
	} else {
		ea &= 0xfffff000;
		esel = kvmppc_e500mc_tlb_index(vcpu_e500mc, ea, tlbsel,
				get_cur_pid(vcpu), -1, vcpu_e500mc->lpid);
		if (esel >= 0)
			kvmppc_e500mc_gtlbe_invalidate(vcpu_e500mc, tlbsel, esel);
	}

	/* TBD: partitioned invalidations, broadcast invalidations */

	_tlbil_all();

	return EMULATE_DONE;
}

int kvmppc_e500mc_emul_tlbilx(struct kvm_vcpu *vcpu, int rt, int ra, int rb)
{
	struct kvmppc_vcpu_e500mc *vcpu_e500mc = to_e500mc(vcpu);
	unsigned int pid, tid;
	int esel, tlbsel;
	gva_t ea;
	struct tlbe *tlbe;

	pid = get_cur_spid(vcpu);

	if (rt == 0 || rt == 1) {
		/* invalidate all entries */
		for (tlbsel = 0; tlbsel < 2; tlbsel++) {
			for (esel = 0;
			     esel < vcpu_e500mc->guest_tlb_size[tlbsel];
			     esel++) {
				tlbe = &vcpu_e500mc->guest_tlb[tlbsel][esel];
				tid = get_tlb_tid(tlbe);
				if ((rt == 0) || (tid == pid))
					kvmppc_e500mc_gtlbe_invalidate(
						vcpu_e500mc, tlbsel, esel);
			}
		}

	} else if (rt == 3) {
		ea =  kvmppc_get_gpr(vcpu, rb);
		if (ra)
			ea += kvmppc_get_gpr(vcpu,ra);

		ea &= ~(PAGE_SIZE - 1);

		for (tlbsel = 0; tlbsel < 2; tlbsel++) {
			esel = kvmppc_e500mc_tlb_index(vcpu_e500mc, ea, tlbsel,
					pid, -1, vcpu_e500mc->lpid);
			if (esel >= 0) {
				kvmppc_e500mc_gtlbe_invalidate(vcpu_e500mc,
					tlbsel, esel);
				break;
			}
		}
	}

	return EMULATE_DONE;
}

int kvmppc_e500mc_emul_tlbre(struct kvm_vcpu *vcpu)
{
	struct kvmppc_vcpu_e500mc *vcpu_e500mc = to_e500mc(vcpu);
	int tlbsel, esel;
	struct tlbe *gtlbe;

	tlbsel = get_tlb_tlbsel(vcpu);
	esel = get_tlb_esel(vcpu, tlbsel);

	gtlbe = &vcpu_e500mc->guest_tlb[tlbsel][esel];

	vcpu->arch.shared->mas0 &= ~MAS0_NV(~0);
	vcpu->arch.shared->mas0 |= MAS0_NV(vcpu_e500mc->guest_tlb_nv[tlbsel]);
	vcpu->arch.shared->mas1 = gtlbe->mas1;
	vcpu->arch.shared->mas2 = gtlbe->mas2;
	vcpu->arch.shared->mas7_3 = ((u64)gtlbe->mas7 << 32) | gtlbe->mas3;

	return EMULATE_DONE;
}

int kvmppc_e500mc_emul_tlbsx(struct kvm_vcpu *vcpu, int rb)
{
	struct kvmppc_vcpu_e500mc *vcpu_e500mc = to_e500mc(vcpu);
	int as = !!get_cur_sas(vcpu);
	unsigned int pid = get_cur_spid(vcpu);
	int esel, tlbsel;
	struct tlbe *gtlbe = NULL;
	gva_t ea;

	ea = kvmppc_get_gpr(vcpu, rb);

	for (tlbsel = 0; tlbsel < 2; tlbsel++) {
		esel = kvmppc_e500mc_tlb_index(vcpu_e500mc, ea, tlbsel, pid, as, vcpu_e500mc->lpid);
		if (esel >= 0) {
			gtlbe = &vcpu_e500mc->guest_tlb[tlbsel][esel];
			break;
		}
	}

	if (gtlbe) {
		vcpu->arch.shared->mas0 = MAS0_TLBSEL(tlbsel) | MAS0_ESEL(esel)
			| MAS0_NV(vcpu_e500mc->guest_tlb_nv[tlbsel]);
		vcpu->arch.shared->mas1 = gtlbe->mas1;
		vcpu->arch.shared->mas2 = gtlbe->mas2;
		vcpu->arch.shared->mas7_3 = ((u64)gtlbe->mas7 << 32) |
					    gtlbe->mas3;
	} else {
		int victim;

		/* since we only have two TLBs, only lower bit is used. */
		tlbsel = vcpu->arch.shared->mas4 >> 28 & 0x1;
		victim = (tlbsel == 0) ? tlb0_get_next_victim(vcpu_e500mc) : 0;

		vcpu->arch.shared->mas0 = MAS0_TLBSEL(tlbsel) | MAS0_ESEL(victim)
			| MAS0_NV(vcpu_e500mc->guest_tlb_nv[tlbsel]);
		vcpu->arch.shared->mas1 = (vcpu->arch.shared->mas6 & MAS6_SPID0)
			| (vcpu->arch.shared->mas6 & (MAS6_SAS ? MAS1_TS : 0))
			| (vcpu->arch.shared->mas4 & MAS4_TSIZED(~0));
		vcpu->arch.shared->mas2 &= MAS2_EPN;
		vcpu->arch.shared->mas2 |= vcpu->arch.shared->mas4 & MAS2_ATTRIB_MASK;
		vcpu->arch.shared->mas7_3 &= MAS3_U0 | MAS3_U1 | MAS3_U2 | MAS3_U3;
	}

	return EMULATE_DONE;
}

int kvmppc_e500mc_emul_tlbwe(struct kvm_vcpu *vcpu)
{
	struct kvmppc_vcpu_e500mc *vcpu_e500mc = to_e500mc(vcpu);
	u64 eaddr;
	u64 raddr;
	u32 tid;
	struct tlbe *gtlbe;
	int tlbsel, esel, stlbsel, sesel;

	tlbsel = get_tlb_tlbsel(vcpu);
	esel = get_tlb_esel(vcpu, tlbsel);

	gtlbe = &vcpu_e500mc->guest_tlb[tlbsel][esel];

	if (get_tlb_v(gtlbe) && tlbsel == 1) {
		eaddr = get_tlb_eaddr(gtlbe);
		tid = get_tlb_tid(gtlbe);
		kvmppc_e500mc_tlb1_invalidate(vcpu_e500mc, eaddr,
				get_tlb_end(gtlbe), tid, vcpu_e500mc->lpid);
	}

	gtlbe->mas1 = vcpu->arch.shared->mas1;
	gtlbe->mas2 = vcpu->arch.shared->mas2;
	gtlbe->mas3 = (u32)vcpu->arch.shared->mas7_3;
	gtlbe->mas7 = vcpu->arch.shared->mas7_3 >> 32;
	gtlbe->mas8 = MAS8_TGS | vcpu_e500mc->lpid;

	trace_kvm_gtlb_write(vcpu->arch.shared->mas0, gtlbe->mas1, gtlbe->mas2,
			     gtlbe->mas3, gtlbe->mas7);

	/* Invalidate shadow mappings for the about-to-be-clobbered TLBE. */
	if (tlbe_is_host_safe(vcpu, gtlbe)) {
		switch (tlbsel) {
		case 0:
			/* TLB0 */
			gtlbe->mas1 &= ~MAS1_TSIZE(~0);
			gtlbe->mas1 |= MAS1_TSIZE(BOOK3E_PAGESZ_4K);

			stlbsel = 0;
			sesel = kvmppc_e500mc_stlbe_map(vcpu_e500mc, 0, esel);

			break;

		case 1:
			/* TLB1 */
			eaddr = get_tlb_eaddr(gtlbe);
			raddr = get_tlb_raddr(gtlbe);

			/* Create a 4KB mapping on the host.
			 * If the guest wanted a large page,
			 * only the first 4KB is mapped here and the rest
			 * are mapped on the fly. */
			stlbsel = 1;
			sesel = kvmppc_e500mc_tlb1_map(vcpu_e500mc, eaddr,
					raddr >> PAGE_SHIFT, gtlbe);
			break;

		default:
			BUG();
		}
		write_host_tlbe(vcpu_e500mc, stlbsel, sesel);
	}

	return EMULATE_DONE;
}

int kvmppc_mmu_itlb_index(struct kvm_vcpu *vcpu, gva_t eaddr)
{
	struct kvmppc_vcpu_e500mc *vcpu_e500mc = to_e500mc(vcpu);
	unsigned int as = !!(vcpu->arch.shared->msr & MSR_IS);

	return kvmppc_e500mc_tlb_search(vcpu, eaddr, get_cur_pid(vcpu), as, vcpu_e500mc->lpid);
}

int kvmppc_mmu_dtlb_index(struct kvm_vcpu *vcpu, gva_t eaddr)
{
	struct kvmppc_vcpu_e500mc *vcpu_e500mc = to_e500mc(vcpu);
	unsigned int as = !!(vcpu->arch.shared->msr & MSR_DS);

	return kvmppc_e500mc_tlb_search(vcpu, eaddr, get_cur_pid(vcpu), as, vcpu_e500mc->lpid);
}

void kvmppc_mmu_itlb_miss(struct kvm_vcpu *vcpu)
{
	unsigned int as = !!(vcpu->arch.shared->msr & MSR_IS);

	kvmppc_e500mc_deliver_tlb_miss(vcpu, vcpu->arch.pc, as);
}

void kvmppc_mmu_dtlb_miss(struct kvm_vcpu *vcpu)
{
	unsigned int as = !!(vcpu->arch.shared->msr & MSR_DS);

	kvmppc_e500mc_deliver_tlb_miss(vcpu, vcpu->arch.fault_dear, as);
}

gpa_t kvmppc_mmu_xlate(struct kvm_vcpu *vcpu, unsigned int index,
			gva_t eaddr)
{
	struct kvmppc_vcpu_e500mc *vcpu_e500mc = to_e500mc(vcpu);
	struct tlbe *gtlbe =
		&vcpu_e500mc->guest_tlb[tlbsel_of(index)][esel_of(index)];
	u64 pgmask = get_tlb_bytes(gtlbe) - 1;

	return get_tlb_raddr(gtlbe) | (eaddr & pgmask);
}

void kvmppc_mmu_destroy(struct kvm_vcpu *vcpu)
{
	struct kvmppc_vcpu_e500mc *vcpu_e500mc = to_e500mc(vcpu);
	int tlbsel, i;

	for (tlbsel = 0; tlbsel < 2; tlbsel++)
		for (i = 0; i < vcpu_e500mc->guest_tlb_size[tlbsel]; i++)
			kvmppc_e500mc_shadow_release(vcpu_e500mc, tlbsel, i);

	/* discard all guest mapping */
	_tlbil_all();
}

void kvmppc_mmu_map(struct kvm_vcpu *vcpu, u64 eaddr, gpa_t gpaddr,
			unsigned int index)
{
	struct kvmppc_vcpu_e500mc *vcpu_e500mc = to_e500mc(vcpu);
	int tlbsel = tlbsel_of(index);
	int esel = esel_of(index);
	int stlbsel, sesel;

	switch (tlbsel) {
	case 0:
		stlbsel = 0;
		sesel = esel;
		break;

	case 1: {
		gfn_t gfn = gpaddr >> PAGE_SHIFT;
		struct tlbe *gtlbe
			= &vcpu_e500mc->guest_tlb[tlbsel][esel];

		stlbsel = 1;
		sesel = kvmppc_e500mc_tlb1_map(vcpu_e500mc, eaddr, gfn, gtlbe);
		break;
	}

	default:
		BUG();
		break;
	}
	write_host_tlbe(vcpu_e500mc, stlbsel, sesel);
}

void kvmppc_set_pid(struct kvm_vcpu *vcpu, u32 pid)
{
	vcpu->arch.shadow_pid = pid;
}

void kvmppc_e500mc_tlb_setup(struct kvmppc_vcpu_e500mc *vcpu_e500mc)
{
	struct tlbe *tlbe;

	/* Insert large initial mapping for guest. */
	tlbe = &vcpu_e500mc->guest_tlb[1][0];
	tlbe->mas1 = MAS1_VALID | MAS1_TSIZE(BOOK3E_PAGESZ_256M);
	tlbe->mas2 = 0;
	tlbe->mas3 = E500MC_TLB_SUPER_PERM_MASK;
	tlbe->mas7 = 0;
	tlbe->mas8 = MAS8_TGS | vcpu_e500mc->lpid;

	/* 4K map for serial output. Used by kernel wrapper. */
	tlbe = &vcpu_e500mc->guest_tlb[1][1];
	tlbe->mas1 = MAS1_VALID | MAS1_TSIZE(BOOK3E_PAGESZ_4K);
	tlbe->mas2 = (0xe0004500 & 0xFFFFF000) | MAS2_I | MAS2_G;
	tlbe->mas3 = (0xe0004500 & 0xFFFFF000) | E500MC_TLB_SUPER_PERM_MASK;
	tlbe->mas7 = 0;
	tlbe->mas8 = MAS8_TGS | vcpu_e500mc->lpid;
}

int kvmppc_e500mc_tlb_init(struct kvmppc_vcpu_e500mc *vcpu_e500mc)
{
	tlb1_entry_num = mfspr(SPRN_TLB1CFG) & 0xFFF;

	vcpu_e500mc->guest_tlb_size[0] = KVM_E500MC_TLB0_SIZE;
	vcpu_e500mc->guest_tlb[0] =
		kzalloc(sizeof(struct tlbe) * KVM_E500MC_TLB0_SIZE, GFP_KERNEL);
	if (vcpu_e500mc->guest_tlb[0] == NULL)
		goto err_out;

	vcpu_e500mc->shadow_tlb_size[0] = KVM_E500MC_TLB0_SIZE;
	vcpu_e500mc->shadow_tlb[0] =
		kzalloc(sizeof(struct tlbe) * KVM_E500MC_TLB0_SIZE, GFP_KERNEL);
	if (vcpu_e500mc->shadow_tlb[0] == NULL)
		goto err_out_guest0;

	vcpu_e500mc->guest_tlb_size[1] = KVM_E500MC_TLB1_SIZE;
	vcpu_e500mc->guest_tlb[1] =
		kzalloc(sizeof(struct tlbe) * KVM_E500MC_TLB1_SIZE, GFP_KERNEL);
	if (vcpu_e500mc->guest_tlb[1] == NULL)
		goto err_out_shadow0;

	vcpu_e500mc->shadow_tlb_size[1] = tlb1_entry_num;
	vcpu_e500mc->shadow_tlb[1] =
		kzalloc(sizeof(struct tlbe) * tlb1_entry_num, GFP_KERNEL);
	if (vcpu_e500mc->shadow_tlb[1] == NULL)
		goto err_out_guest1;

	vcpu_e500mc->shadow_pages[0] = (struct page **)
		kzalloc(sizeof(struct page *) * KVM_E500MC_TLB0_SIZE, GFP_KERNEL);
	if (vcpu_e500mc->shadow_pages[0] == NULL)
		goto err_out_shadow1;

	vcpu_e500mc->shadow_pages[1] = (struct page **)
		kzalloc(sizeof(struct page *) * tlb1_entry_num, GFP_KERNEL);
	if (vcpu_e500mc->shadow_pages[1] == NULL)
		goto err_out_page0;

	/* Init TLB configuration register */
	vcpu_e500mc->tlb0cfg = mfspr(SPRN_TLB0CFG) & ~0xfffUL;
	vcpu_e500mc->tlb0cfg |= vcpu_e500mc->guest_tlb_size[0];
	vcpu_e500mc->tlb1cfg = mfspr(SPRN_TLB1CFG) & ~0xfffUL;
	vcpu_e500mc->tlb1cfg |= vcpu_e500mc->guest_tlb_size[1];

	return 0;

err_out_page0:
	kfree(vcpu_e500mc->shadow_pages[0]);
err_out_shadow1:
	kfree(vcpu_e500mc->shadow_tlb[1]);
err_out_guest1:
	kfree(vcpu_e500mc->guest_tlb[1]);
err_out_shadow0:
	kfree(vcpu_e500mc->shadow_tlb[0]);
err_out_guest0:
	kfree(vcpu_e500mc->guest_tlb[0]);
err_out:
	return -1;
}

void kvmppc_e500mc_tlb_uninit(struct kvmppc_vcpu_e500mc *vcpu_e500mc)
{
	kfree(vcpu_e500mc->shadow_pages[1]);
	kfree(vcpu_e500mc->shadow_pages[0]);
	kfree(vcpu_e500mc->shadow_tlb[1]);
	kfree(vcpu_e500mc->guest_tlb[1]);
	kfree(vcpu_e500mc->shadow_tlb[0]);
	kfree(vcpu_e500mc->guest_tlb[0]);
}
