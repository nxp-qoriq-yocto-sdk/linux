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
#include <linux/log2.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/rwsem.h>
#include <linux/vmalloc.h>
#include <asm/kvm_ppc.h>
#include <asm/kvm_e500mc.h>

#include "../mm/mmu_decl.h"
#include "e500mc_tlb.h"
#include "trace.h"

#define to_htlb1_esel(esel) (tlb1_entry_num - (esel) - 1)

static unsigned int tlb1_entry_num;

static struct kvm_book3e_206_tlb_entry *
get_entry(struct kvmppc_vcpu_e500mc *vcpu_e500mc, int tlbsel, int entry)
{
	int offset = vcpu_e500mc->gtlb_offset[tlbsel];
	return &vcpu_e500mc->gtlb_arch[offset + entry];
}

void kvmppc_dump_tlbs(struct kvm_vcpu *vcpu)
{
	struct kvmppc_vcpu_e500mc *vcpu_e500mc = to_e500mc(vcpu);
	struct kvm_book3e_206_tlb_entry *tlbe;
	int i, tlbsel;

	printk("| %8s | %8s | %16s | %16s |\n",
	       "nr", "mas1", "mas2", "mas7_3");

	for (tlbsel = 0; tlbsel < 2; tlbsel++) {
		int offset = vcpu_e500mc->gtlb_offset[tlbsel];

		printk("Guest TLB%d:\n", tlbsel);
		for (i = 0; i < vcpu_e500mc->gtlb_size[tlbsel]; i++) {
			tlbe = &vcpu_e500mc->gtlb_arch[offset + i];
			if (tlbe->mas1 & MAS1_VALID)
				printk(" G[%d][%3d] |  %08X | %016llX | %016llX |\n",
				       tlbsel, i, tlbe->mas1,
				       (unsigned long long)tlbe->mas2,
				       (unsigned long long)tlbe->mas7_3);
		}
	}
}

static int tlb0_set_base(struct kvmppc_vcpu_e500mc *vcpu_e500mc, gva_t addr)
{
	int set_base;

	set_base = (addr >> PAGE_SHIFT) & (vcpu_e500mc->gtlb0_sets - 1);
	set_base *= vcpu_e500mc->gtlb0_ways;

	return set_base;
}

static int get_tlb_esel(struct kvm_vcpu *vcpu, int tlbsel)
{
	struct kvmppc_vcpu_e500mc *vcpu_e500mc = to_e500mc(vcpu);
	int esel = get_tlb_esel_bit(vcpu);

	if (tlbsel == 0) {
		esel &= vcpu_e500mc->gtlb0_ways - 1;
		esel += tlb0_set_base(vcpu_e500mc, vcpu->arch.shared->mas2);
	} else {
		esel &= vcpu_e500mc->gtlb_size[1] - 1;
	}

	return esel;
}

/* Search the guest TLB for a matching entry. */
static int kvmppc_e500mc_tlb_index(struct kvmppc_vcpu_e500mc *vcpu_e500mc,
		gva_t eaddr, int tlbsel, unsigned int pid, int as,
		unsigned int lpid)
{
	int size = vcpu_e500mc->gtlb_size[tlbsel];
	int set_base, offset;
	int i;

	if (tlbsel == 0) {
		set_base = tlb0_set_base(vcpu_e500mc, eaddr);
		size = vcpu_e500mc->gtlb0_ways;
	} else {
		set_base = 0;
	}

	offset = vcpu_e500mc->gtlb_offset[tlbsel];

	/* XXX Replace loop with fancy data structures. */
	for (i = 0; i < size; i++) {
		struct kvm_book3e_206_tlb_entry *tlbe =
			&vcpu_e500mc->gtlb_arch[offset + set_base + i];
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

		return set_base + i;
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

	victim = vcpu_e500mc->gtlb_nv[0]++;
	if (unlikely(vcpu_e500mc->gtlb_nv[0] >= vcpu_e500mc->gtlb0_ways))
		vcpu_e500mc->gtlb_nv[0] = 0;

	return victim;
}

static inline unsigned int tlb1_max_shadow_size(void)
{
	return tlb1_entry_num - tlbcam_index;
}

static inline int tlbe_is_writable(struct kvm_book3e_206_tlb_entry *tlbe)
{
	return tlbe->mas7_3 & (MAS3_SW|MAS3_UW);
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
static inline void __write_host_tlbe(struct kvm_book3e_206_tlb_entry *stlbe,
				     uint32_t mas0)
{
	local_irq_disable();

	mtspr(SPRN_MAS0, mas0);
	mtspr(SPRN_MAS1, stlbe->mas1);
	mtspr(SPRN_MAS2, (unsigned long)stlbe->mas2);
	mtspr(SPRN_MAS3, (u32)stlbe->mas7_3);
	mtspr(SPRN_MAS7, (u32)(stlbe->mas7_3 >> 32));
	mtspr(SPRN_MAS8, stlbe->mas8);
	asm volatile("isync; tlbwe" : : : "memory");

	/* Must clear mas8 for other host tlbwe's */
	mtspr(SPRN_MAS8, 0);
	isync();

	local_irq_enable();
}

static inline void write_host_tlbe(struct kvmppc_vcpu_e500mc *vcpu_e500mc,
		int tlbsel, int esel, struct kvm_book3e_206_tlb_entry *stlbe)
{
	if (tlbsel == 0) {
		int way = esel & (vcpu_e500mc->gtlb0_ways - 1);
		__write_host_tlbe(stlbe, MAS0_TLBSEL(0) | MAS0_ESEL(way));
	} else {
		__write_host_tlbe(stlbe,
				  MAS0_TLBSEL(1) |
				  MAS0_ESEL(to_htlb1_esel(esel)));
	}
	trace_kvm_stlb_write(index_of(tlbsel, esel), stlbe->mas1, stlbe->mas2,
	                     (u32)stlbe->mas7_3, (u32)(stlbe->mas7_3 >> 32));
}

void kvmppc_e500mc_tlb_load(struct kvm_vcpu *vcpu, int cpu)
{
	struct kvmppc_vcpu_e500mc *vcpu_e500mc = to_e500mc(vcpu);

	if (vcpu_e500mc->oldpir != mfspr(SPRN_PIR)) {
		mtspr(SPRN_MAS5, MAS5_SGS | (vcpu_e500mc->lpid & 0xFF));
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

static void kvmppc_e500mc_tlb1_invalidate(
		struct kvmppc_vcpu_e500mc *vcpu_e500mc, int esel, u32 eaddr)
{
	struct tlbe_priv *priv;
	u64 tmp;
	int hw_tlb_indx;
	unsigned long flags;

	local_irq_save(flags);

	priv = &vcpu_e500mc->gtlb_priv[1][esel];
	tmp = priv->hw_tlbe_bitmap;
	while (tmp) {
		hw_tlb_indx = __ilog2_u64(tmp & ~(tmp - 1));
		mtspr(SPRN_MAS0,
			  MAS0_TLBSEL(1) |
			  MAS0_ESEL(to_htlb1_esel(hw_tlb_indx)));
		mtspr(SPRN_MAS1, 0);
		asm volatile ("tlbwe\n" : : );
		vcpu_e500mc->rmap_gtlbe[hw_tlb_indx] = 0;
		tmp &= (tmp - 1);
	}
	mb();
	priv->hw_tlbe_bitmap = 0;

	local_irq_restore(flags);
}

static void kvmppc_e500mc_stlbe_invalidate(
		struct kvmppc_vcpu_e500mc *vcpu_e500mc,
		int tlbsel, int esel)
{
	struct kvm_book3e_206_tlb_entry *gtlbe =
		get_entry(vcpu_e500mc, tlbsel, esel);
	unsigned int tid, ts;
	u32 val, eaddr, lpid;
	unsigned long flags;

	ts = get_tlb_ts(gtlbe);
	tid = get_tlb_tid(gtlbe);
	lpid = get_tlb_lpid(gtlbe);

	/* We search host TLB0 to invalidate it's shadow TLBe */
	val = (tid << 16) | ts;
	eaddr = get_tlb_eaddr(gtlbe);

	if (tlbsel == 1) {
		kvmppc_e500mc_tlb1_invalidate(vcpu_e500mc, esel, eaddr);
		return;
	}

	local_irq_save(flags);

	mtspr(SPRN_MAS6, val);
	mtspr(SPRN_MAS5, MAS5_SGS | lpid);

	asm volatile ( "tlbsx 0, %[eaddr]\n" : : [eaddr] "a"(eaddr));
	val = mfspr(SPRN_MAS1);
	if (val & MAS1_VALID) {
		mtspr(SPRN_MAS1, val & ~MAS1_VALID);
		asm volatile ("tlbwe\n" : : );
	}
	mtspr(SPRN_MAS5, 0);
	/* NOTE: tlbsx also updates mas8, hence clear it for host tlbwe's */
	mtspr(SPRN_MAS8, 0);
	isync();

	local_irq_restore(flags);
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
		| MAS0_NV(vcpu_e500mc->gtlb_nv[tlbsel]);
	vcpu->arch.shared->mas1 = MAS1_VALID | (as ? MAS1_TS : 0)
		| MAS1_TID(vcpu->arch.pid)
		| MAS1_TSIZE(tsized);
	vcpu->arch.shared->mas2 = (eaddr & MAS2_EPN)
		| (vcpu->arch.shared->mas4 & MAS2_ATTRIB_MASK);
	vcpu->arch.shared->mas7_3 &= MAS3_U0 | MAS3_U1 | MAS3_U2 | MAS3_U3;
	vcpu->arch.shared->mas6 = (vcpu->arch.shared->mas6 & MAS6_SPID1)
		| (get_cur_pid(vcpu) << 16)
		| (as ? MAS6_SAS : 0);
}

static inline void kvmppc_e500mc_setup_stlbe(
	struct kvmppc_vcpu_e500mc *vcpu_e500mc,
        struct kvm_book3e_206_tlb_entry *gtlbe, int tsize,
        struct tlbe_priv *priv, u64 gvaddr,
        struct kvm_book3e_206_tlb_entry *stlbe)
{
	pfn_t pfn = priv->pfn;

	/* Force TS=1 IPROT=0 for all guest mappings. */
	stlbe->mas1 = MAS1_TSIZE(tsize)
		| MAS1_TID(get_tlb_tid(gtlbe)) | (gtlbe->mas1 & MAS1_TS) | MAS1_VALID;
	stlbe->mas2 = (gvaddr & MAS2_EPN)
		| e500mc_shadow_mas2_attrib(gtlbe->mas2,
				vcpu_e500mc->vcpu.arch.shared->msr & MSR_PR);
	stlbe->mas7_3 = ((u64)pfn << PAGE_SHIFT)
		| e500mc_shadow_mas3_attrib(gtlbe->mas7_3,
				vcpu_e500mc->vcpu.arch.shared->msr & MSR_PR);
	stlbe->mas8 = MAS8_TGS | vcpu_e500mc->lpid;
}

static inline void kvmppc_e500mc_priv_setup(struct tlbe_priv *priv,
                                          struct kvm_book3e_206_tlb_entry *gtlbe,
                                          pfn_t pfn)
{
	priv->pfn = pfn;
	priv->flags = E500MC_TLB_VALID;

	if (tlbe_is_writable(gtlbe))
		priv->flags |= E500MC_TLB_DIRTY;
}

static inline void kvmppc_e500mc_priv_release(struct tlbe_priv *priv)
{
	if (priv->flags & E500MC_TLB_VALID) {
		if (priv->flags & E500MC_TLB_DIRTY)
			kvm_release_pfn_dirty(priv->pfn);
		else
			kvm_release_pfn_clean(priv->pfn);

		priv->flags = 0;
	}
}

static inline int kvmppc_e500mc_setup_virt_mmio(
	struct kvmppc_vcpu_e500mc *vcpu_e500mc, int esel,
	struct kvm_book3e_206_tlb_entry *stlbe)
{
	struct kvm_book3e_206_tlb_entry *gtlbe = get_entry(vcpu_e500mc, 0, esel);
	struct tlbe_priv *priv;
	unsigned long flags;
	int sesel;

	/* Force GS=1 IPROT=0, 4K Page size for all virt. mmio mappings. */
	stlbe->mas1 = MAS1_TSIZE(BOOK3E_PAGESZ_4K) | MAS1_VALID |
		MAS1_TID(get_tlb_tid(gtlbe)) | (gtlbe->mas1 & MAS1_TS);
	stlbe->mas2 = (get_tlb_eaddr(gtlbe) & MAS2_EPN)
		| e500mc_shadow_mas2_attrib(gtlbe->mas2,
				vcpu_e500mc->vcpu.arch.shared->msr & MSR_PR);
	stlbe->mas7_3 = e500mc_shadow_mas3_attrib(gtlbe->mas7_3,
				vcpu_e500mc->vcpu.arch.shared->msr & MSR_PR);
	stlbe->mas8 = MAS8_TGS | vcpu_e500mc->lpid | MAS8_VF;

	priv = &vcpu_e500mc->gtlb_priv[0][esel];
	kvmppc_e500mc_priv_release(priv);

	/* Get a next-victim hint from the hardware */
	local_irq_save(flags);

	mtspr(SPRN_MAS6, 0); /* don't care about addr space, just way usage */
	asm volatile("tlbsx 0, %0" : : "b" (stlbe->mas2));
	sesel = MAS0_NV(mfspr(SPRN_MAS0));

	local_irq_restore(flags);

	return sesel;
}

static inline void kvmppc_e500mc_shadow_map(
	struct kvmppc_vcpu_e500mc *vcpu_e500mc,
	u64 gvaddr, gfn_t gfn, struct kvm_book3e_206_tlb_entry *gtlbe,
	int tlbsel, int esel, struct kvm_book3e_206_tlb_entry *stlbe)
{
	struct kvm_memory_slot *slot;
	unsigned long pfn, hva;
	int pfnmap = 0;
	int tsize = BOOK3E_PAGESZ_4K;
	struct tlbe_priv *priv;

	/*
	 * Translate guest physical to true physical, acquiring
	 * a page reference if it is normal, non-reserved memory.
	 *
	 * gfn_to_memslot() must succeed because otherwise we wouldn't
	 * have gotten this far.  Eventually we should just pass the slot
	 * pointer through from the first lookup.
	 */
	slot = gfn_to_memslot(vcpu_e500mc->vcpu.kvm, gfn);
	hva = gfn_to_hva_memslot(slot, gfn);

	if (tlbsel == 1) {
		struct vm_area_struct *vma;
		down_read(&current->mm->mmap_sem);

		vma = find_vma(current->mm, hva);
		if (vma && hva >= vma->vm_start &&
		    (vma->vm_flags & VM_PFNMAP)) {
			/*
			 * This VMA is a physically contiguous region (e.g.
			 * /dev/mem) that bypasses normal Linux page
			 * management.  Find the overlap between the
			 * vma and the memslot.
			 */

			unsigned long start, end;
			unsigned long slot_start, slot_end;

			pfnmap = 1;

			start = vma->vm_pgoff;
			end = start +
			      ((vma->vm_end - vma->vm_start) >> PAGE_SHIFT);

			pfn = start + ((hva - vma->vm_start) >> PAGE_SHIFT);

			slot_start = pfn - (gfn - slot->base_gfn);
			slot_end = slot_start + slot->npages;

			if (start < slot_start)
				start = slot_start;
			if (end > slot_end)
				end = slot_end;

			tsize = (gtlbe->mas1 & MAS1_TSIZE_MASK) >>
				MAS1_TSIZE_SHIFT;

			/*
			 * e500 doesn't implement the lowest tsize bit,
			 * or 1K pages.
			 */
			tsize = max(BOOK3E_PAGESZ_4K, tsize & ~1);

			/*
			 * Now find the largest tsize (up to what the guest
			 * requested) that will cover gfn, stay within the
			 * range, and for which gfn and pfn are mutually
			 * aligned.
			 */

			for (; tsize > BOOK3E_PAGESZ_4K; tsize -= 2) {
				unsigned long gfn_start, gfn_end, tsize_pages;
				tsize_pages = 1 << (tsize - 2);

				gfn_start = gfn & ~(tsize_pages - 1);
				gfn_end = gfn_start + tsize_pages;

				if (gfn_start + pfn - gfn < start)
					continue;
				if (gfn_end + pfn - gfn > end)
					continue;
				if ((gfn & (tsize_pages - 1)) !=
				    (pfn & (tsize_pages - 1)))
					continue;

				gvaddr &= ~((tsize_pages << PAGE_SHIFT) - 1);
				pfn &= ~(tsize_pages - 1);
				break;
			}
		}

		up_read(&current->mm->mmap_sem);
	}

	if (likely(!pfnmap)) {
		pfn = gfn_to_pfn_memslot(vcpu_e500mc->vcpu.kvm, slot, gfn);
		if (is_error_pfn(pfn)) {
			printk(KERN_ERR "Couldn't get real page for gfn %lx!\n",
					(long)gfn);
			kvm_release_pfn_clean(pfn);
			return;
		}
	}

	/* Drop old priv and setup new one. */
	priv = &vcpu_e500mc->gtlb_priv[tlbsel][esel];
	kvmppc_e500mc_priv_release(priv);
	kvmppc_e500mc_priv_setup(priv, gtlbe, pfn);

	kvmppc_e500mc_setup_stlbe(vcpu_e500mc, gtlbe, tsize, priv, gvaddr, stlbe);

}

/* XXX only map the one-one case, for now use TLB0 */
static int kvmppc_e500mc_tlb0_map(struct kvmppc_vcpu_e500mc *vcpu_e500mc,
                                int esel, struct kvm_book3e_206_tlb_entry *stlbe)
{
	struct kvm_book3e_206_tlb_entry *gtlbe;
	unsigned long flags;
	int sesel;

	gtlbe = get_entry(vcpu_e500mc, 0, esel);

	kvmppc_e500mc_shadow_map(vcpu_e500mc, get_tlb_eaddr(gtlbe),
			get_tlb_raddr(gtlbe) >> PAGE_SHIFT,
			gtlbe, 0, esel, stlbe);

	/* Get a next-victim hint from the hardware */
	local_irq_save(flags);

	mtspr(SPRN_MAS6, 0); /* don't care about addr space, just way usage */
	asm volatile("tlbsx 0, %0" : : "b" (stlbe->mas2));
	sesel = MAS0_NV(mfspr(SPRN_MAS0));

	local_irq_restore(flags);

	return sesel;
}

/* Caller must ensure that the specified guest TLB entry is safe to insert into
 * the shadow TLB. */
/* XXX for both one-one and one-to-many , for now use TLB1 */
static int kvmppc_e500mc_tlb1_map(struct kvmppc_vcpu_e500mc *vcpu_e500mc,
		u64 gvaddr, gfn_t gfn, struct kvm_book3e_206_tlb_entry *gtlbe,
		struct kvm_book3e_206_tlb_entry *stlbe, int esel)
{
	unsigned int victim;
	struct tlbe_priv *priv;

	victim = vcpu_e500mc->gtlb_nv[1]++;

	if (unlikely(vcpu_e500mc->gtlb_nv[1] >= tlb1_max_shadow_size()))
		vcpu_e500mc->gtlb_nv[1] = 0;

	kvmppc_e500mc_shadow_map(vcpu_e500mc, gvaddr, gfn, gtlbe, 1, victim, stlbe);

	priv = &vcpu_e500mc->gtlb_priv[1][esel];
	priv->hw_tlbe_bitmap |= (u64) 1 << victim;
	if (vcpu_e500mc->rmap_gtlbe[victim]) {
		priv = &vcpu_e500mc->gtlb_priv[1]
			[vcpu_e500mc->rmap_gtlbe[victim]];
		priv->hw_tlbe_bitmap &= ~((u64) 1 << victim);
	}
	vcpu_e500mc->rmap_gtlbe[victim] = esel;

	return victim;
}

static inline int kvmppc_e500mc_gtlbe_invalidate(
				struct kvmppc_vcpu_e500mc *vcpu_e500mc,
				int tlbsel, int esel)
{
	struct kvm_book3e_206_tlb_entry *gtlbe =
		get_entry(vcpu_e500mc, tlbsel, esel);

	if (unlikely(get_tlb_iprot(gtlbe)))
		return -1;

	kvmppc_e500mc_stlbe_invalidate(vcpu_e500mc, tlbsel, esel);

	gtlbe->mas1 = 0;

	return 0;
}

int kvmppc_e500mc_emul_mt_mmucsr0(
	struct kvmppc_vcpu_e500mc *vcpu_e500mc, ulong value)
{
	int esel;

	if (value & MMUCSR0_TLB0FI)
		for (esel = 0; esel < vcpu_e500mc->gtlb_size[0]; esel++)
			kvmppc_e500mc_gtlbe_invalidate(vcpu_e500mc, 0, esel);
	if (value & MMUCSR0_TLB1FI)
		for (esel = 0; esel < vcpu_e500mc->gtlb_size[1]; esel++)
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
		for (esel = 0; esel < vcpu_e500mc->gtlb_size[tlbsel]; esel++)
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
	struct kvm_book3e_206_tlb_entry *tlbe;

	pid = get_cur_spid(vcpu);

	if (rt == 0 || rt == 1) {
		/* invalidate all entries */
		for (tlbsel = 0; tlbsel < 2; tlbsel++) {
			for (esel = 0;
			     esel < vcpu_e500mc->gtlb_size[tlbsel];
			     esel++) {
				tlbe = get_entry(vcpu_e500mc, tlbsel, esel);
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
	struct kvm_book3e_206_tlb_entry *gtlbe;

	tlbsel = get_tlb_tlbsel(vcpu);
	esel = get_tlb_esel(vcpu, tlbsel);

	gtlbe = get_entry(vcpu_e500mc, tlbsel, esel);

	vcpu->arch.shared->mas0 &= ~MAS0_NV(~0);
	vcpu->arch.shared->mas0 |= MAS0_NV(vcpu_e500mc->gtlb_nv[tlbsel]);
	vcpu->arch.shared->mas1 = gtlbe->mas1;
	vcpu->arch.shared->mas2 = gtlbe->mas2;
	vcpu->arch.shared->mas7_3 = gtlbe->mas7_3;

	return EMULATE_DONE;
}

int kvmppc_e500mc_emul_tlbsx(struct kvm_vcpu *vcpu, int rb)
{
	struct kvmppc_vcpu_e500mc *vcpu_e500mc = to_e500mc(vcpu);
	int as = !!get_cur_sas(vcpu);
	unsigned int pid = get_cur_spid(vcpu);
	int esel, tlbsel;
	struct kvm_book3e_206_tlb_entry *gtlbe = NULL;
	gva_t ea;

	ea = kvmppc_get_gpr(vcpu, rb);

	for (tlbsel = 0; tlbsel < 2; tlbsel++) {
		esel = kvmppc_e500mc_tlb_index(vcpu_e500mc, ea, tlbsel, pid, as, vcpu_e500mc->lpid);
		if (esel >= 0) {
			gtlbe = get_entry(vcpu_e500mc, tlbsel, esel);
			break;
		}
	}

	if (gtlbe) {
		vcpu->arch.shared->mas0 = MAS0_TLBSEL(tlbsel) | MAS0_ESEL(esel)
			| MAS0_NV(vcpu_e500mc->gtlb_nv[tlbsel]);
		vcpu->arch.shared->mas1 = gtlbe->mas1;
		vcpu->arch.shared->mas2 = gtlbe->mas2;
		vcpu->arch.shared->mas7_3 = gtlbe->mas7_3;
	} else {
		int victim;

		/* since we only have two TLBs, only lower bit is used. */
		tlbsel = vcpu->arch.shared->mas4 >> 28 & 0x1;
		victim = (tlbsel == 0) ? tlb0_get_next_victim(vcpu_e500mc) : 0;

		vcpu->arch.shared->mas0 = MAS0_TLBSEL(tlbsel) | MAS0_ESEL(victim)
			| MAS0_NV(vcpu_e500mc->gtlb_nv[tlbsel]);
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
	struct kvm_book3e_206_tlb_entry *gtlbe;
	int tlbsel, esel, stlbsel, sesel;
	struct kvm_book3e_206_tlb_entry stlbe;

	tlbsel = get_tlb_tlbsel(vcpu);
	esel = get_tlb_esel(vcpu, tlbsel);

	gtlbe = get_entry(vcpu_e500mc, tlbsel, esel);

	if (get_tlb_v(gtlbe))
		kvmppc_e500mc_stlbe_invalidate(vcpu_e500mc, tlbsel, esel);

	gtlbe->mas1 = vcpu->arch.shared->mas1;
	gtlbe->mas2 = vcpu->arch.shared->mas2;
	gtlbe->mas7_3 = vcpu->arch.shared->mas7_3;
	gtlbe->mas8 = MAS8_TGS | vcpu_e500mc->lpid;

	trace_kvm_gtlb_write(vcpu->arch.shared->mas0, gtlbe->mas1, gtlbe->mas2,
			     (u32)gtlbe->mas7_3, (u32)(gtlbe->mas7_3 >> 32));

	/* Invalidate shadow mappings for the about-to-be-clobbered TLBE. */
	preempt_disable();
	if (tlbe_is_host_safe(vcpu, gtlbe)) {
		u64 eaddr;
		u64 raddr;

		switch (tlbsel) {
		case 0:
			/* TLB0 */
			gtlbe->mas1 &= ~MAS1_TSIZE(~0);
			gtlbe->mas1 |= MAS1_TSIZE(BOOK3E_PAGESZ_4K);

			stlbsel = 0;
			sesel = kvmppc_e500mc_tlb0_map(vcpu_e500mc, esel, &stlbe);

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
					raddr >> PAGE_SHIFT, gtlbe, &stlbe,
					esel);
			break;

		default:
			BUG();
		}
		write_host_tlbe(vcpu_e500mc, stlbsel, sesel, &stlbe);
	} else if (tlbsel == 0) {
		/* MMU emulation support via VF mechanism */
		gtlbe->mas1 &= ~MAS1_TSIZE(~0);
		gtlbe->mas1 |= MAS1_TSIZE(BOOK3E_PAGESZ_4K);

		sesel = kvmppc_e500mc_setup_virt_mmio(vcpu_e500mc, esel, &stlbe);
		write_host_tlbe(vcpu_e500mc, 0, sesel, &stlbe);
	}
	preempt_enable();

	return EMULATE_DONE;
}

int kvmppc_mmu_itlb_index(struct kvm_vcpu *vcpu, gva_t eaddr)
{
	struct kvmppc_vcpu_e500mc *vcpu_e500mc = to_e500mc(vcpu);
	unsigned int as = !!(vcpu->arch.shared->msr & MSR_IS);

	return kvmppc_e500mc_tlb_search(vcpu, eaddr, get_cur_pid(vcpu), as,
				vcpu_e500mc->lpid);
}

int kvmppc_mmu_dtlb_index(struct kvm_vcpu *vcpu, gva_t eaddr)
{
	struct kvmppc_vcpu_e500mc *vcpu_e500mc = to_e500mc(vcpu);
	unsigned int as = !!(vcpu->arch.shared->msr & MSR_DS);

	return kvmppc_e500mc_tlb_search(vcpu, eaddr, get_cur_pid(vcpu), as,
				 vcpu_e500mc->lpid);
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
	struct kvm_book3e_206_tlb_entry *gtlbe =
		 get_entry(vcpu_e500mc, tlbsel_of(index), esel_of(index));
	u64 pgmask = get_tlb_bytes(gtlbe) - 1;

	return get_tlb_raddr(gtlbe) | (eaddr & pgmask);
}

void kvmppc_mmu_destroy(struct kvm_vcpu *vcpu)
{
}

void kvmppc_mmu_map(struct kvm_vcpu *vcpu, u64 eaddr, gpa_t gpaddr,
			unsigned int index)
{
	struct kvmppc_vcpu_e500mc *vcpu_e500mc = to_e500mc(vcpu);
	struct tlbe_priv *priv;
	struct kvm_book3e_206_tlb_entry *gtlbe, stlbe;
	int tlbsel = tlbsel_of(index);
	int esel = esel_of(index);
	int stlbsel, sesel;

	gtlbe = get_entry(vcpu_e500mc, tlbsel, esel);

	preempt_disable();
	switch (tlbsel) {
	case 0:
		stlbsel = 0;
		sesel = esel;
		priv = &vcpu_e500mc->gtlb_priv[stlbsel][sesel];

		kvmppc_e500mc_setup_stlbe(vcpu_e500mc, gtlbe, BOOK3E_PAGESZ_4K,
		                        priv, eaddr, &stlbe);
		break;

	case 1: {
		gfn_t gfn = gpaddr >> PAGE_SHIFT;

		stlbsel = 1;
		sesel = kvmppc_e500mc_tlb1_map(vcpu_e500mc, eaddr, gfn, gtlbe,
						 &stlbe, esel);
		break;
	}

	default:
		BUG();
		break;
	}

	write_host_tlbe(vcpu_e500mc, stlbsel, sesel, &stlbe);
	preempt_enable();
}

void kvmppc_set_pid(struct kvm_vcpu *vcpu, u32 pid)
{
	vcpu->arch.pid = pid;
}

u32 kvmppc_get_mmucfg(struct kvm_vcpu *vcpu)
{
	return mfspr(SPRN_MMUCFG) & ~MMUCFG_LPIDSIZE;
}

void kvmppc_e500mc_tlb_setup(struct kvmppc_vcpu_e500mc *vcpu_e500mc)
{
	struct kvm_book3e_206_tlb_entry *tlbe;

	/* Insert large initial mapping for guest. */
	tlbe = get_entry(vcpu_e500mc, 1, 0);
	tlbe->mas1 = MAS1_VALID | MAS1_TSIZE(BOOK3E_PAGESZ_2GB);
	tlbe->mas2 = 0;
	tlbe->mas7_3 = E500MC_TLB_SUPER_PERM_MASK;
	tlbe->mas8 = MAS8_TGS | vcpu_e500mc->lpid;

	/* 4K map for serial output. Used by kernel wrapper. */
	tlbe = get_entry(vcpu_e500mc, 1, 1);
	tlbe->mas1 = MAS1_VALID | MAS1_TSIZE(BOOK3E_PAGESZ_4K);
	tlbe->mas2 = (0xe0004500 & 0xFFFFF000) | MAS2_I | MAS2_G;
	tlbe->mas7_3 = (0xe0004500 & 0xFFFFF000) | E500MC_TLB_SUPER_PERM_MASK;
	tlbe->mas8 = MAS8_TGS | vcpu_e500mc->lpid;
}

static void clear_tlb_privs(struct kvmppc_vcpu_e500mc *vcpu_e500mc)
{
	int stlbsel, i;

	for (stlbsel = 0; stlbsel < 2; stlbsel++) {
		for (i = 0; i < vcpu_e500mc->gtlb_size[stlbsel]; i++) {
			struct tlbe_priv *priv =
				&vcpu_e500mc->gtlb_priv[stlbsel][i];
			kvmppc_e500mc_priv_release(priv);
		}
	}
}

static void free_gtlb(struct kvmppc_vcpu_e500mc *vcpu_e500mc)
{
	int i;

	clear_tlb_privs(vcpu_e500mc);

	kfree(vcpu_e500mc->gtlb_priv[0]);
	kfree(vcpu_e500mc->gtlb_priv[1]);

	if (vcpu_e500mc->shared_tlb_pages) {
		vfree((void *)(round_down((uintptr_t)vcpu_e500mc->gtlb_arch,
					  PAGE_SIZE)));

		for (i = 0; i < vcpu_e500mc->num_shared_tlb_pages; i++)
			put_page(vcpu_e500mc->shared_tlb_pages[i]);

		vcpu_e500mc->num_shared_tlb_pages = 0;
		vcpu_e500mc->shared_tlb_pages = NULL;
	} else {
		kfree(vcpu_e500mc->gtlb_arch);
	}

	vcpu_e500mc->gtlb_arch = NULL;
}

int kvm_vcpu_ioctl_config_tlb(struct kvm_vcpu *vcpu,
			      struct kvm_config_tlb *cfg)
{
	struct kvmppc_vcpu_e500mc *vcpu_e500mc = to_e500mc(vcpu);
	struct kvm_book3e_206_tlb_params params;
	char *virt;
	struct page **pages;
	struct tlbe_priv *privs[2] = {};
	size_t array_len;
	u32 sets;
	int num_pages, ret, i;
	unsigned long flags;

	if (cfg->mmu_type != KVM_MMU_FSL_BOOKE_NOHV)
		return -EINVAL;

	if (copy_from_user(&params, (void __user *)(uintptr_t)cfg->params,
			   sizeof(params)))
		return -EFAULT;

	if (params.tlb_sizes[1] > 64)
		return -EINVAL;
	if (params.tlb_sizes[2] != 0 || params.tlb_sizes[3] != 0)
		return -EINVAL;
	if (params.tlb_ways[1] != 0 || params.tlb_ways[2] != 0 ||
	    params.tlb_ways[3] != 0)
		return -EINVAL;

	if (!is_power_of_2(params.tlb_ways[0]))
		return -EINVAL;

	sets = params.tlb_sizes[0] >> ilog2(params.tlb_ways[0]);
	if (!is_power_of_2(sets))
		return -EINVAL;

	array_len = params.tlb_sizes[0] + params.tlb_sizes[1];
	array_len *= sizeof(struct kvm_book3e_206_tlb_entry);

	if (cfg->array_len < array_len)
		return -EINVAL;

	num_pages = DIV_ROUND_UP(cfg->array + array_len - 1, PAGE_SIZE) -
		    cfg->array / PAGE_SIZE;
	pages = kmalloc(sizeof(struct page *) * num_pages, GFP_KERNEL);
	if (!pages)
		return -ENOMEM;

	ret = get_user_pages_fast(cfg->array, num_pages, 1, pages);
	if (ret < 0)
		goto err_pages;

	if (ret != num_pages) {
		num_pages = ret;
		ret = -EFAULT;
		goto err_put_page;
	}

	virt = vmap(pages, num_pages, VM_MAP, PAGE_KERNEL);
	if (!virt)
		goto err_put_page;

	privs[0] = kzalloc(sizeof(struct tlbe_priv) * params.tlb_sizes[0],
			   GFP_KERNEL);
	privs[1] = kzalloc(sizeof(struct tlbe_priv) * params.tlb_sizes[1],
			   GFP_KERNEL);

	if (!privs[0] || !privs[1])
		goto err_put_page;

	local_irq_save(flags);
	mtspr(SPRN_MAS5, MAS5_SGS | (vcpu_e500mc->lpid & 0xFF));
	asm volatile("tlbilxlpid");
	mtspr(SPRN_MAS5, 0);
	local_irq_restore(flags);

	free_gtlb(vcpu_e500mc);

	vcpu_e500mc->gtlb_priv[0] = privs[0];
	vcpu_e500mc->gtlb_priv[1] = privs[1];

	vcpu_e500mc->gtlb_arch = (struct kvm_book3e_206_tlb_entry *)
		(virt + (cfg->array & (PAGE_SIZE - 1)));

	vcpu_e500mc->gtlb_size[0] = params.tlb_sizes[0];
	vcpu_e500mc->gtlb_size[1] = params.tlb_sizes[1];

	vcpu_e500mc->gtlb_offset[0] = 0;
	vcpu_e500mc->gtlb_offset[1] = params.tlb_sizes[0];

	vcpu_e500mc->tlb0cfg = mfspr(SPRN_TLB0CFG) & ~0xfffUL;
	if (params.tlb_sizes[0] <= 2048)
		vcpu_e500mc->tlb0cfg |= params.tlb_sizes[0];

	vcpu_e500mc->tlb1cfg = mfspr(SPRN_TLB1CFG) & ~0xfffUL;
	vcpu_e500mc->tlb1cfg |= params.tlb_sizes[1];

	vcpu_e500mc->shared_tlb_pages = pages;
	vcpu_e500mc->num_shared_tlb_pages = num_pages;

	vcpu_e500mc->gtlb0_ways = params.tlb_ways[0];
	vcpu_e500mc->gtlb0_sets = sets;

	return 0;

err_put_page:
	kfree(privs[0]);
	kfree(privs[1]);

	for (i = 0; i < num_pages; i++)
		put_page(pages[i]);

err_pages:
	kfree(pages);
	return ret;
}

int kvm_vcpu_ioctl_dirty_tlb(struct kvm_vcpu *vcpu,
			     struct kvm_dirty_tlb *dirty)
{
	struct kvmppc_vcpu_e500mc *vcpu_e500mc = to_e500mc(vcpu);
	unsigned long flags;

	local_irq_save(flags);
	mtspr(SPRN_MAS5, MAS5_SGS | (vcpu_e500mc->lpid & 0xFF));
	asm volatile("tlbilxlpid");
	mtspr(SPRN_MAS5, 0);
	local_irq_restore(flags);

	clear_tlb_privs(vcpu_e500mc);

	return 0;
}

void kvmppc_core_heavy_exit(struct kvm_vcpu *vcpu)
{
	struct kvmppc_vcpu_e500mc *vcpu_e500mc = to_e500mc(vcpu);
	int i;

	/*
	 * We may have modified the guest TLB, so mark it dirty.
	 * We only do it on an actual return to userspace, to avoid
	 * adding more overhead to getting scheduled out -- and avoid
	 * any locking issues with getting preempted in the middle of
	 * KVM_CONFIG_TLB, etc.
	 */

	for (i = 0; i < vcpu_e500mc->num_shared_tlb_pages; i++)
		set_page_dirty_lock(vcpu_e500mc->shared_tlb_pages[i]);
}

int kvmppc_e500mc_tlb_init(struct kvmppc_vcpu_e500mc *vcpu_e500mc)
{
	int entry_size = sizeof(struct kvm_book3e_206_tlb_entry);
	int entries = KVM_E500MC_TLB0_SIZE + KVM_E500MC_TLB1_SIZE;

	tlb1_entry_num = mfspr(SPRN_TLB1CFG) & 0xFFF;
	vcpu_e500mc->rmap_gtlbe =
		 kzalloc(sizeof(unsigned int) * tlb1_entry_num, GFP_KERNEL);
	if (!vcpu_e500mc->rmap_gtlbe)
		return -ENOMEM;

	vcpu_e500mc->gtlb_size[0] = KVM_E500MC_TLB0_SIZE;
	vcpu_e500mc->gtlb_size[1] = KVM_E500MC_TLB1_SIZE;

	vcpu_e500mc->gtlb0_ways = KVM_E500MC_TLB0_WAY_NUM;
	vcpu_e500mc->gtlb0_sets = KVM_E500MC_TLB0_SIZE / KVM_E500MC_TLB0_WAY_NUM;

	vcpu_e500mc->gtlb_arch = kmalloc(entries * entry_size, GFP_KERNEL);
	if (!vcpu_e500mc->gtlb_arch)
		return -ENOMEM;

	vcpu_e500mc->gtlb_offset[0] = 0;
	vcpu_e500mc->gtlb_offset[1] = KVM_E500MC_TLB0_SIZE;

	vcpu_e500mc->gtlb_priv[0] =
		kzalloc(sizeof(struct tlbe_priv) * KVM_E500MC_TLB0_SIZE,
			GFP_KERNEL);
	if (vcpu_e500mc->gtlb_priv[0] == NULL)
		goto err;
	vcpu_e500mc->gtlb_priv[1] =
		kzalloc(sizeof(struct tlbe_priv) * KVM_E500MC_TLB1_SIZE,
			 GFP_KERNEL);

	if (vcpu_e500mc->gtlb_priv[1] == NULL)
		goto err;

	/* Init TLB configuration register */
	vcpu_e500mc->tlb0cfg = mfspr(SPRN_TLB0CFG) & ~0xfffUL;
	vcpu_e500mc->tlb0cfg |= vcpu_e500mc->gtlb_size[0];
	vcpu_e500mc->tlb1cfg = mfspr(SPRN_TLB1CFG) & ~0xfffUL;
	vcpu_e500mc->tlb1cfg |= vcpu_e500mc->gtlb_size[1];

	return 0;

err:
	free_gtlb(vcpu_e500mc);
	return -1;
}

void kvmppc_e500mc_tlb_uninit(struct kvmppc_vcpu_e500mc *vcpu_e500mc)
{
	free_gtlb(vcpu_e500mc);
}
