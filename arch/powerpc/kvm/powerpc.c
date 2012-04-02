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
 * Copyright (C) 2010-2011 Freescale Semiconductor, Inc.
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 *          Christian Ehrhardt <ehrhardt@linux.vnet.ibm.com>
 */

#include <linux/errno.h>
#include <linux/err.h>
#include <linux/kvm_host.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/hrtimer.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <asm/cputable.h>
#include <asm/uaccess.h>
#include <asm/kvm_ppc.h>
#include <asm/tlbflush.h>
#include <asm/cputhreads.h>
#include <asm/pmc.h>
#include "timing.h"
#include "../mm/mmu_decl.h"

#define CREATE_TRACE_POINTS
#include "trace.h"
#include "booke.h"
#include "irq.h"

#ifdef CONFIG_KVM_BOOKE206_PERFMON
static DEFINE_SPINLOCK(perfmon_lock);
static unsigned int perfmon_refcount;
#endif

int kvm_arch_vcpu_runnable(struct kvm_vcpu *v)
{
	bool ret = !!(v->arch.pending_exceptions) ||
	       v->requests;

#ifdef CONFIG_BOOKE
	ret = ret || (v->arch.tsr & TCR_WRC_MASK);
#endif

	return ret;
}

int kvmppc_kvm_pv(struct kvm_vcpu *vcpu)
{
	int nr = kvmppc_get_gpr(vcpu, 11);
	int r;
	unsigned long __maybe_unused param1 = kvmppc_get_gpr(vcpu, 3);
	unsigned long __maybe_unused param2 = kvmppc_get_gpr(vcpu, 4);
	unsigned long __maybe_unused param3 = kvmppc_get_gpr(vcpu, 5);
	unsigned long __maybe_unused param4 = kvmppc_get_gpr(vcpu, 6);
	unsigned long r2 = 0;

	if (!(vcpu->arch.shared->msr & MSR_SF)) {
		/* 32 bit mode */
		param1 &= 0xffffffff;
		param2 &= 0xffffffff;
		param3 &= 0xffffffff;
		param4 &= 0xffffffff;
	}

	switch (nr) {
	case KVM_HCALL_TOKEN(KVM_HC_PPC_MAP_MAGIC_PAGE):
	{
		vcpu->arch.magic_page_pa = param1;
		vcpu->arch.magic_page_ea = param2;

		r2 = KVM_MAGIC_FEAT_SR | KVM_MAGIC_FEAT_MAS0_TO_SPRG7;

		if (irqchip_in_kernel(vcpu->kvm))
			r2 |= KVM_MAGIC_FEAT_EPR | KVM_MAGIC_FEAT_MPIC_CTPR;

		r = EV_SUCCESS;
		break;
	}
	case KVM_HCALL_TOKEN(KVM_HC_FEATURES):
		r = EV_SUCCESS;
#if defined(CONFIG_PPC_BOOK3S) || defined(CONFIG_KVM_E500V2)
		/* XXX Missing magic page on 44x */
		r2 |= (1 << KVM_FEATURE_MAGIC_PAGE);
#endif

		/* Second return value is in r4 */
		break;
	case EV_HCALL_TOKEN(EV_IDLE):
		r = EV_SUCCESS;
		kvm_vcpu_block(vcpu);
		clear_bit(KVM_REQ_UNHALT, &vcpu->requests);
		break;
	default:
		r = EV_UNIMPLEMENTED;
		break;
	}

	kvmppc_set_gpr(vcpu, 4, r2);

	return r;
}

int kvmppc_sanity_check(struct kvm_vcpu *vcpu)
{
	int r = false;

	/* We have to know what CPU to virtualize */
	if (!vcpu->arch.pvr)
		goto out;

	/* PAPR only works with book3s_64 */
	if ((vcpu->arch.cpu_type != KVM_CPU_3S_64) && vcpu->arch.papr_enabled)
		goto out;

#ifdef CONFIG_KVM_BOOK3S_64_HV
	/* HV KVM can only do PAPR mode for now */
	if (!vcpu->arch.papr_enabled)
		goto out;
#endif

#ifdef CONFIG_KVM_BOOKE_HV
	if (!cpu_has_feature(CPU_FTR_EMB_HV))
		goto out;
#endif

	r = true;

out:
	vcpu->arch.sane = r;
	return r ? 0 : -EINVAL;
}

int kvmppc_emulate_mmio(struct kvm_run *run, struct kvm_vcpu *vcpu)
{
	enum emulation_result er;
	int r;

	er = kvmppc_emulate_instruction(run, vcpu);
	switch (er) {
	case EMULATE_DONE:
		/* Future optimization: only reload non-volatiles if they were
		 * actually modified. */
		r = RESUME_GUEST_NV;
		break;
	case EMULATE_DO_MMIO:
		run->exit_reason = KVM_EXIT_MMIO;
		/* We must reload nonvolatiles because "update" load/store
		 * instructions modify register state. */
		/* Future optimization: only reload non-volatiles if they were
		 * actually modified. */
		r = RESUME_HOST_NV;
		break;
	case EMULATE_FAIL:
		/* XXX Deliver Program interrupt to guest. */
		printk(KERN_EMERG "%s: emulation failed (%08x)\n", __func__,
		       kvmppc_get_last_inst(vcpu));
		r = RESUME_HOST;
		break;
	default:
		BUG();
	}

	return r;
}

int kvm_arch_hardware_enable(void *garbage)
{
	return 0;
}

void kvm_arch_hardware_disable(void *garbage)
{
}

int kvm_arch_hardware_setup(void)
{
	return 0;
}

void kvm_arch_hardware_unsetup(void)
{
}

void kvm_arch_check_processor_compat(void *rtn)
{
	*(int *)rtn = kvmppc_core_check_processor_compat();
}

int kvm_arch_init_vm(struct kvm *kvm)
{
	int ret;

	ret = kvmppc_core_init_vm(kvm);
	if (ret)
		return ret;

	INIT_LIST_HEAD(&kvm->arch.assigned_dev_head);
	return 0;
}

void kvm_arch_destroy_vm(struct kvm *kvm)
{
	unsigned int i;
	struct kvm_vcpu *vcpu;

	kvm_for_each_vcpu(i, vcpu, kvm)
		kvm_arch_vcpu_free(vcpu);

	mutex_lock(&kvm->lock);
	for (i = 0; i < atomic_read(&kvm->online_vcpus); i++)
		kvm->vcpus[i] = NULL;

	atomic_set(&kvm->online_vcpus, 0);

	kvmppc_core_destroy_vm(kvm);

	mutex_unlock(&kvm->lock);
}

void kvm_arch_sync_events(struct kvm *kvm)
{
#ifdef CONFIG_KVM_MPIC
	kvm_free_all_assigned_devices(kvm);
#endif
}

int kvm_dev_ioctl_check_extension(long ext)
{
	int r;

	switch (ext) {
#ifdef CONFIG_BOOKE
	case KVM_CAP_PPC_BOOKE_SREGS:
#else
	case KVM_CAP_PPC_SEGSTATE:
	case KVM_CAP_PPC_HIOR:
	case KVM_CAP_PPC_PAPR:
#endif
	case KVM_CAP_PPC_UNSET_IRQ:
	case KVM_CAP_PPC_IRQ_LEVEL:
	case KVM_CAP_ENABLE_CAP:
	case KVM_CAP_ONE_REG:
		r = 1;
		break;
#ifndef CONFIG_KVM_BOOK3S_64_HV
	case KVM_CAP_PPC_PAIRED_SINGLES:
	case KVM_CAP_PPC_OSI:
	case KVM_CAP_PPC_GET_PVINFO:
#if defined(CONFIG_KVM_E500V2) || defined(CONFIG_KVM_E500MC)
	case KVM_CAP_SW_TLB:
#endif
#ifdef CONFIG_KVM_BOOKE206_PERFMON
	case KVM_CAP_ENABLE_PERFMON:
#endif
#ifdef CONFIG_KVM_MPIC
	case KVM_CAP_IRQCHIP:
	case KVM_CAP_IRQ_INJECT_STATUS:
	case KVM_CAP_SYSTEM_IRQ_ASSIGNMENT:
#endif
		r = 1;
		break;
	case KVM_CAP_COALESCED_MMIO:
		r = KVM_COALESCED_MMIO_PAGE_OFFSET;
		break;
#endif
#ifdef CONFIG_KVM_BOOK3S_64_HV
	case KVM_CAP_SPAPR_TCE:
		r = 1;
		break;
	case KVM_CAP_PPC_SMT:
		r = threads_per_core;
		break;
	case KVM_CAP_PPC_RMA:
		r = 1;
		/* PPC970 requires an RMA */
		if (cpu_has_feature(CPU_FTR_ARCH_201))
			r = 2;
		break;
	case KVM_CAP_SYNC_MMU:
		r = cpu_has_feature(CPU_FTR_ARCH_206) ? 1 : 0;
		break;
#endif
	default:
		r = 0;
		break;
	}
	return r;

}

long kvm_arch_dev_ioctl(struct file *filp,
                        unsigned int ioctl, unsigned long arg)
{
	return -EINVAL;
}

int kvm_arch_prepare_memory_region(struct kvm *kvm,
                                   struct kvm_memory_slot *memslot,
                                   struct kvm_memory_slot old,
                                   struct kvm_userspace_memory_region *mem,
                                   int user_alloc)
{
	return kvmppc_core_prepare_memory_region(kvm, mem);
}

void kvm_arch_commit_memory_region(struct kvm *kvm,
               struct kvm_userspace_memory_region *mem,
               struct kvm_memory_slot old,
               int user_alloc)
{
	kvmppc_core_commit_memory_region(kvm, mem);
}


void kvm_arch_flush_shadow(struct kvm *kvm)
{
}

struct kvm_vcpu *kvm_arch_vcpu_create(struct kvm *kvm, unsigned int id)
{
	struct kvm_vcpu *vcpu;
	int ret;

	/*
	 * To avoid (possibly malicious) races where userspace
	 * does something like create an irqchip at the same time
	 * as creating a vcpu, we forbid such vm init after the
	 * first vcpu is created, rather than using existing mechanisms
	 * which can only tell whether a vcpu has come online.
	 */
	mutex_lock(&kvm->lock);
	kvm->arch.vm_init_done = 1;
	mutex_unlock(&kvm->lock);

	vcpu = kvmppc_core_vcpu_create(kvm, id);
	if (IS_ERR(vcpu))
		return vcpu;

	vcpu->arch.wqp = &vcpu->wq;
	kvmppc_create_vcpu_debugfs(vcpu, id);

	ret = kvm_arch_irqchip_add_vcpu(vcpu);
	if (ret < 0)
		goto err;

	return vcpu;

err:
	kvmppc_remove_vcpu_debugfs(vcpu);
	kvmppc_core_vcpu_free(vcpu);
	return ERR_PTR(ret);
}

void kvm_arch_vcpu_free(struct kvm_vcpu *vcpu)
{
	/* Make sure we're not using the vcpu anymore */
	hrtimer_cancel(&vcpu->arch.dec_timer);
	tasklet_kill(&vcpu->arch.tasklet);

#ifdef CONFIG_KVM_MPIC
	kvm_arch_irqchip_remove_vcpu(vcpu);
#endif

	kvmppc_remove_vcpu_debugfs(vcpu);
	kvmppc_core_vcpu_free(vcpu);
}

void kvm_arch_vcpu_destroy(struct kvm_vcpu *vcpu)
{
	kvm_arch_vcpu_free(vcpu);
}

int kvm_cpu_has_pending_timer(struct kvm_vcpu *vcpu)
{
	return kvmppc_core_pending_dec(vcpu);
}

/*
 * low level hrtimer wake routine. Because this runs in hardirq context
 * we schedule a tasklet to do the real work.
 */
enum hrtimer_restart kvmppc_decrementer_wakeup(struct hrtimer *timer)
{
	struct kvm_vcpu *vcpu;

	vcpu = container_of(timer, struct kvm_vcpu, arch.dec_timer);
	tasklet_schedule(&vcpu->arch.tasklet);

	return HRTIMER_NORESTART;
}

int kvm_arch_vcpu_init(struct kvm_vcpu *vcpu)
{
	hrtimer_init(&vcpu->arch.dec_timer, CLOCK_REALTIME, HRTIMER_MODE_ABS);
	tasklet_init(&vcpu->arch.tasklet, kvmppc_decrementer_func, (ulong)vcpu);
	vcpu->arch.dec_timer.function = kvmppc_decrementer_wakeup;
	vcpu->arch.dec_expires = ~(u64)0;

#ifdef CONFIG_KVM_EXIT_TIMING
	mutex_init(&vcpu->arch.exit_timing_lock);
#endif

#ifdef CONFIG_BOOKE
	setup_timer(&vcpu->arch.wdt_timer, kvmppc_watchdog_func,
	            (unsigned long)vcpu);
#endif
	return 0;
}

void kvm_arch_vcpu_uninit(struct kvm_vcpu *vcpu)
{
#ifdef CONFIG_BOOKE
	del_timer(&vcpu->arch.wdt_timer);
#endif
#ifdef CONFIG_KVM_BOOKE206_PERFMON
	if (vcpu->arch.pm_is_reserved) {
		spin_lock(&perfmon_lock);
		vcpu->arch.pm_is_reserved = false;

		if (!(--perfmon_refcount))
			release_pmc_hardware();
		spin_unlock(&perfmon_lock);
	}
#endif
	kvmppc_mmu_destroy(vcpu);
}

void kvm_arch_vcpu_load(struct kvm_vcpu *vcpu, int cpu)
{
#ifdef CONFIG_BOOKE
	/*
	 * vrsave (formerly usprg0) isn't used by Linux, but may
	 * be used by the guest.
	 *
	 * On non-booke this is associated with Altivec and
	 * is handled by code in book3s.c.
	 */
	mtspr(SPRN_VRSAVE, vcpu->arch.vrsave);
#endif
	kvmppc_core_vcpu_load(vcpu, cpu);
	vcpu->cpu = smp_processor_id();
}

void kvm_arch_vcpu_put(struct kvm_vcpu *vcpu)
{
	kvmppc_core_vcpu_put(vcpu);
#ifdef CONFIG_BOOKE
	vcpu->arch.vrsave = mfspr(SPRN_VRSAVE);
#endif
	vcpu->cpu = -1;
}

int kvm_arch_vcpu_ioctl_set_guest_debug(struct kvm_vcpu *vcpu,
                                        struct kvm_guest_debug *dbg)
{
	return kvmppc_core_set_guest_debug(vcpu, dbg);
}

static void kvmppc_complete_dcr_load(struct kvm_vcpu *vcpu,
                                     struct kvm_run *run)
{
	kvmppc_set_gpr(vcpu, vcpu->arch.io_gpr, run->dcr.data);
}

static void kvmppc_complete_load(struct kvm_vcpu *vcpu, void *data,
				 unsigned int len, int is_big_endian,
				 int is_sign_extend, unsigned int rt)
{
	u64 uninitialized_var(gpr);

	if (len > sizeof(gpr)) {
		printk(KERN_ERR "bad MMIO length: %d\n", len);
		return;
	}

	if (is_big_endian) {
		switch (len) {
		case 8: gpr = *(u64 *)data; break;
		case 4: gpr = *(u32 *)data; break;
		case 2: gpr = *(u16 *)data; break;
		case 1: gpr = *(u8 *)data; break;
		}
	} else {
		/* Convert BE data from userland back to LE. */
		switch (len) {
		case 4: gpr = ld_le32((u32 *)data); break;
		case 2: gpr = ld_le16((u16 *)data); break;
		case 1: gpr = *(u8 *)data; break;
		}
	}

	if (is_sign_extend) {
		switch (len) {
#ifdef CONFIG_PPC64
		case 4:
			gpr = (s64)(s32)gpr;
			break;
#endif
		case 2:
			gpr = (s64)(s16)gpr;
			break;
		case 1:
			gpr = (s64)(s8)gpr;
			break;
		}
	}

	kvmppc_set_gpr(vcpu, rt, gpr);

	switch (rt & KVM_MMIO_REG_EXT_MASK) {
	case KVM_MMIO_REG_GPR:
		kvmppc_set_gpr(vcpu, rt, gpr);
		break;
	case KVM_MMIO_REG_FPR:
		vcpu->arch.fpr[rt & KVM_MMIO_REG_MASK] = gpr;
		break;
#ifdef CONFIG_PPC_BOOK3S
	case KVM_MMIO_REG_QPR:
		vcpu->arch.qpr[rt & KVM_MMIO_REG_MASK] = gpr;
		break;
	case KVM_MMIO_REG_FQPR:
		vcpu->arch.fpr[rt & KVM_MMIO_REG_MASK] = gpr;
		vcpu->arch.qpr[rt & KVM_MMIO_REG_MASK] = gpr;
		break;
#endif
	default:
		BUG();
	}
}

int kvmppc_handle_load(struct kvm_run *run, struct kvm_vcpu *vcpu,
                       unsigned int rt, unsigned int bytes, int is_bigendian)
{
	u64 addr = vcpu->arch.paddr_accessed;
	ulong val;

	if (!kvm_io_bus_read(vcpu->kvm, KVM_MMIO_BUS,
				addr, bytes, &val)) {
		kvmppc_complete_load(vcpu, &val, bytes, is_bigendian, 0, rt);
		return EMULATE_DONE;
	}

	if (bytes > sizeof(run->mmio.data)) {
		printk(KERN_ERR "%s: bad MMIO length: %d\n", __func__,
		       run->mmio.len);
	}

	run->mmio.phys_addr = addr;
	run->mmio.len = bytes;
	run->mmio.is_write = 0;

	vcpu->arch.io_gpr = rt;
	vcpu->arch.mmio_is_bigendian = is_bigendian;
	vcpu->mmio_needed = 1;
	vcpu->mmio_is_write = 0;
	vcpu->arch.mmio_sign_extend = 0;

	return EMULATE_DO_MMIO;
}

/* Same as above, but sign extends */
int kvmppc_handle_loads(struct kvm_run *run, struct kvm_vcpu *vcpu,
                        unsigned int rt, unsigned int bytes, int is_bigendian)
{
	u64 addr = vcpu->arch.paddr_accessed;
	ulong val;

	if (!kvm_io_bus_read(vcpu->kvm, KVM_MMIO_BUS,
				addr, bytes, &val)) {
		kvmppc_complete_load(vcpu, &val, bytes, is_bigendian, 1, rt);
		return EMULATE_DONE;
	}

	if (bytes > sizeof(run->mmio.data)) {
		printk(KERN_ERR "%s: bad MMIO length: %d\n", __func__,
		       run->mmio.len);
	}

	run->mmio.phys_addr = addr;
	run->mmio.len = bytes;
	run->mmio.is_write = 0;

	vcpu->arch.io_gpr = rt;
	vcpu->arch.mmio_is_bigendian = is_bigendian;
	vcpu->mmio_needed = 1;
	vcpu->mmio_is_write = 0;
	vcpu->arch.mmio_sign_extend = 1;

	return EMULATE_DO_MMIO;
}

int kvmppc_handle_store(struct kvm_run *run, struct kvm_vcpu *vcpu,
                        u64 val, unsigned int bytes, int is_bigendian)
{
	u64 addr = vcpu->arch.paddr_accessed;
	void *data = run->mmio.data;

	if (bytes > sizeof(run->mmio.data)) {
		printk(KERN_ERR "%s: bad MMIO length: %d\n", __func__,
		       run->mmio.len);
	}

	/* Store the value at the lowest bytes in 'data'. */
	if (is_bigendian) {
		switch (bytes) {
		case 8: *(u64 *)data = val; break;
		case 4: *(u32 *)data = val; break;
		case 2: *(u16 *)data = val; break;
		case 1: *(u8  *)data = val; break;
		}
	} else {
		/* Store LE value into 'data'. */
		switch (bytes) {
		case 4: st_le32(data, val); break;
		case 2: st_le16(data, val); break;
		case 1: *(u8 *)data = val; break;
		}
	}

	if (!kvm_io_bus_write(vcpu->kvm, KVM_MMIO_BUS, addr, bytes, data))
		return EMULATE_DONE;

	run->mmio.phys_addr = addr;
	run->mmio.len = bytes;
	run->mmio.is_write = 1;
	vcpu->mmio_needed = 1;
	vcpu->mmio_is_write = 1;

	return EMULATE_DO_MMIO;
}

int kvm_arch_vcpu_ioctl_run(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	int r;
	sigset_t sigsaved;

	if (vcpu->sigset_active)
		sigprocmask(SIG_SETMASK, &vcpu->sigset, &sigsaved);

	if (vcpu->mmio_needed) {
		if (!vcpu->mmio_is_write)
			kvmppc_complete_load(vcpu, run->mmio.data,
					     run->mmio.len,
					     vcpu->arch.mmio_is_bigendian,
					     vcpu->arch.mmio_sign_extend,
					     vcpu->arch.io_gpr);
		vcpu->mmio_needed = 0;
	} else if (vcpu->arch.dcr_needed) {
		if (!vcpu->arch.dcr_is_write)
			kvmppc_complete_dcr_load(vcpu, run);
		vcpu->arch.dcr_needed = 0;
	} else if (vcpu->arch.osi_needed) {
		u64 *gprs = run->osi.gprs;
		int i;

		for (i = 0; i < 32; i++)
			kvmppc_set_gpr(vcpu, i, gprs[i]);
		vcpu->arch.osi_needed = 0;
	} else if (vcpu->arch.hcall_needed) {
		int i;

		kvmppc_set_gpr(vcpu, 3, run->papr_hcall.ret);
		for (i = 0; i < 9; ++i)
			kvmppc_set_gpr(vcpu, 4 + i, run->papr_hcall.args[i]);
		vcpu->arch.hcall_needed = 0;
	}

	r = kvmppc_vcpu_run(run, vcpu);

	if (vcpu->sigset_active)
		sigprocmask(SIG_SETMASK, &sigsaved, NULL);

	return r;
}

void kvm_vcpu_kick(struct kvm_vcpu *vcpu)
{
	int me;
	int cpu = vcpu->cpu;

	me = get_cpu();
	if (waitqueue_active(vcpu->arch.wqp)) {
		wake_up_interruptible(vcpu->arch.wqp);
		vcpu->stat.halt_wakeup++;
	} else if (cpu != me && cpu != -1) {
		smp_send_reschedule(vcpu->cpu);
	}
	put_cpu();
}

int kvm_vcpu_ioctl_interrupt(struct kvm_vcpu *vcpu, struct kvm_interrupt *irq)
{
	if (irq->irq == KVM_INTERRUPT_UNSET) {
		kvmppc_core_dequeue_external(vcpu, irq);
		return 0;
	}

	kvmppc_core_queue_external(vcpu, irq);
	kvm_vcpu_kick(vcpu);

	return 0;
}

static int kvm_vcpu_ioctl_enable_cap(struct kvm_vcpu *vcpu,
				     struct kvm_enable_cap *cap)
{
	int r;

	if (cap->flags)
		return -EINVAL;

	switch (cap->cap) {
	case KVM_CAP_PPC_OSI:
		r = 0;
		vcpu->arch.osi_enabled = true;
		break;
	case KVM_CAP_PPC_PAPR:
		r = 0;
		vcpu->arch.papr_enabled = true;
		break;
#if defined(CONFIG_KVM_E500V2) || defined(CONFIG_KVM_E500MC)
	case KVM_CAP_SW_TLB: {
		struct kvm_config_tlb cfg;
		void __user *user_ptr = (void __user *)(uintptr_t)cap->args[0];

		r = -EFAULT;
		if (copy_from_user(&cfg, user_ptr, sizeof(cfg)))
			break;

		r = kvm_vcpu_ioctl_config_tlb(vcpu, &cfg);
		break;
	}
#endif
	default:
		r = -EINVAL;
		break;
	}

	if (!r)
		r = kvmppc_sanity_check(vcpu);

	return r;
}

#ifdef CONFIG_KVM_BOOKE206_PERFMON
static void kvm_perfmon_interrupt_handler(struct pt_regs *regs)
{
	struct kvm_vcpu *vcpu = current->thread.kvm_vcpu;

#ifdef CONFIG_KVM_BOOKE_HV
	vcpu->arch.pm_reg.pmgc0 = vcpu->arch.shadow_pm_reg.pmgc0;
#endif

	if (!vcpu || !vcpu->arch.pm_is_reserved) {
		mtpmr(PMRN_PMGC0, mfpmr(PMRN_PMGC0) & ~PMGC0_PMIE);
		pr_warning("%s KVM: Guest PerfMon Interrupt taken"
			" in kernel\n", __func__);
		return;
	}

	if (vcpu->arch.pm_reg.pmgc0 & PMGC0_FCECE)
		vcpu->arch.pm_reg.pmgc0 |= PMGC0_FAC;

	kvmppc_update_perfmon_ints(vcpu);
}
#endif

static int kvm_arch_vcpu_ioctl_reserve_perfmon(struct kvm_vcpu *vcpu)
{
#ifdef CONFIG_KVM_BOOKE206_PERFMON
	spin_lock(&perfmon_lock);

	if ((!perfmon_refcount) &&
			(reserve_pmc_hardware(kvm_perfmon_interrupt_handler)))
		goto err;

	perfmon_refcount++;
	vcpu->arch.pm_is_reserved = true;
#ifdef CONFIG_KVM_BOOKE_HV
	mtspr(SPRN_MSRP, mfspr(SPRN_MSRP) & ~MSRP_PMMP);
#endif
	spin_unlock(&perfmon_lock);
	return 0;
err:
	spin_unlock(&perfmon_lock);
	return -EBUSY;
#else
	return -EINVAL;
#endif
}

int kvm_arch_vcpu_ioctl_get_mpstate(struct kvm_vcpu *vcpu,
                                    struct kvm_mp_state *mp_state)
{
	return -EINVAL;
}

int kvm_arch_vcpu_ioctl_set_mpstate(struct kvm_vcpu *vcpu,
                                    struct kvm_mp_state *mp_state)
{
	return -EINVAL;
}

long kvm_arch_vcpu_ioctl(struct file *filp,
                         unsigned int ioctl, unsigned long arg)
{
	struct kvm_vcpu *vcpu = filp->private_data;
	void __user *argp = (void __user *)arg;
	long r;

	switch (ioctl) {
	case KVM_INTERRUPT: {
		struct kvm_interrupt irq;
		r = -EFAULT;
		if (copy_from_user(&irq, argp, sizeof(irq)))
			goto out;
		r = kvm_vcpu_ioctl_interrupt(vcpu, &irq);
		goto out;
	}

	case KVM_ENABLE_CAP:
	{
		struct kvm_enable_cap cap;
		r = -EFAULT;
		if (copy_from_user(&cap, argp, sizeof(cap)))
			goto out;
		r = kvm_vcpu_ioctl_enable_cap(vcpu, &cap);
		break;
	}

	case KVM_SET_ONE_REG:
	case KVM_GET_ONE_REG:
	{
		struct kvm_one_reg reg;
		r = -EFAULT;
		if (copy_from_user(&reg, argp, sizeof(reg)))
			goto out;
		if (ioctl == KVM_SET_ONE_REG)
			r = kvm_vcpu_ioctl_set_one_reg(vcpu, &reg);
		else
			r = kvm_vcpu_ioctl_get_one_reg(vcpu, &reg);
		break;
	}

#if defined(CONFIG_KVM_E500V2) || defined(CONFIG_KVM_E500MC)
	case KVM_DIRTY_TLB: {
		struct kvm_dirty_tlb dirty;
		r = -EFAULT;
		if (copy_from_user(&dirty, argp, sizeof(dirty)))
			goto out;
		r = kvm_vcpu_ioctl_dirty_tlb(vcpu, &dirty);
		break;
	}
#endif

	case KVM_RESERVE_PERFMON: {
		r = kvm_arch_vcpu_ioctl_reserve_perfmon(vcpu);
		break;
	}

	default:
		r = -EINVAL;
	}

out:
	return r;
}

static int kvm_vm_ioctl_get_pvinfo(struct kvm_ppc_pvinfo *pvinfo)
{
	u32 inst_nop = 0x60000000;
#ifdef CONFIG_KVM_BOOKE_HV
	u32 inst_sc1 = 0x44000022;
	pvinfo->hcall[0] = inst_sc1;
	pvinfo->hcall[1] = inst_nop;
	pvinfo->hcall[2] = inst_nop;
	pvinfo->hcall[3] = inst_nop;
#else
	u32 inst_lis = 0x3c000000;
	u32 inst_ori = 0x60000000;
	u32 inst_sc = 0x44000002;
	u32 inst_imm_mask = 0xffff;

	/*
	 * The hypercall to get into KVM from within guest context is as
	 * follows:
	 *
	 *    lis r0, r0, KVM_SC_MAGIC_R0@h
	 *    ori r0, KVM_SC_MAGIC_R0@l
	 *    sc
	 *    nop
	 */
	pvinfo->hcall[0] = inst_lis | ((KVM_SC_MAGIC_R0 >> 16) & inst_imm_mask);
	pvinfo->hcall[1] = inst_ori | (KVM_SC_MAGIC_R0 & inst_imm_mask);
	pvinfo->hcall[2] = inst_sc;
	pvinfo->hcall[3] = inst_nop;
#endif

	pvinfo->flags = KVM_PPC_PVINFO_FLAGS_EV_IDLE;

	return 0;
}

long kvm_arch_vm_ioctl(struct file *filp,
                       unsigned int ioctl, unsigned long arg)
{
#ifdef CONFIG_KVM_MPIC
	struct kvm *kvm = filp->private_data;
#endif /* CONFIG_KVM_MPIC */
	void __user *argp = (void __user *)arg;
	long r;

	switch (ioctl) {
	case KVM_PPC_GET_PVINFO: {
		struct kvm_ppc_pvinfo pvinfo;
		memset(&pvinfo, 0, sizeof(pvinfo));
		r = kvm_vm_ioctl_get_pvinfo(&pvinfo);
		if (copy_to_user(argp, &pvinfo, sizeof(pvinfo))) {
			r = -EFAULT;
			goto out;
		}

		break;
	}
#ifdef CONFIG_KVM_BOOK3S_64_HV
	case KVM_CREATE_SPAPR_TCE: {
		struct kvm_create_spapr_tce create_tce;
		struct kvm *kvm = filp->private_data;

		r = -EFAULT;
		if (copy_from_user(&create_tce, argp, sizeof(create_tce)))
			goto out;
		r = kvm_vm_ioctl_create_spapr_tce(kvm, &create_tce);
		goto out;
	}

	case KVM_ALLOCATE_RMA: {
		struct kvm *kvm = filp->private_data;
		struct kvm_allocate_rma rma;

		r = kvm_vm_ioctl_allocate_rma(kvm, &rma);
		if (r >= 0 && copy_to_user(argp, &rma, sizeof(rma)))
			r = -EFAULT;
		break;
	}
#endif /* CONFIG_KVM_BOOK3S_64_HV */
#ifdef CONFIG_KVM_MPIC
	case KVM_CREATE_IRQCHIP: {
		struct kvm_pic *vpic;

		mutex_lock(&kvm->lock);

		r = -EPERM;
		if (kvm->arch.vm_init_done)
			goto create_irqchip_unlock;

		r = -EEXIST;
		if (kvm->arch.vpic)
			goto create_irqchip_unlock;

		r = -ENOMEM;
		vpic = kvm_create_pic(kvm);
		if (!vpic)
			goto create_irqchip_unlock;

		smp_wmb();
		kvm->arch.vpic = vpic;
		smp_wmb();

		r = 0;
create_irqchip_unlock:
		mutex_unlock(&kvm->lock);
		break;
	}
	case KVM_IRQ_LINE_STATUS:
	case KVM_IRQ_LINE: {
		struct kvm_irq_level irq_event;
		s32 status;

		r = -EFAULT;
		if (copy_from_user(&irq_event, argp, sizeof irq_event))
			goto out;

		r = -ENXIO;
		if (!irqchip_in_kernel(kvm))
			goto out;

		status = kvm_arch_set_irqnum(kvm, irq_event.irq,
					     irq_event.level);
		if (ioctl == KVM_IRQ_LINE_STATUS) {
			r = -EFAULT;
			irq_event.status = status;
			if (copy_to_user(argp, &irq_event, sizeof(irq_event)))
				goto out;
		}

		r = 0;
		break;
	}
#endif /* CONFIG_KVM_MPIC */
	default:
		r = -ENOTTY;
	}

out:
	return r;
}

static unsigned long lpid_inuse[BITS_TO_LONGS(KVMPPC_NR_LPIDS)];
static unsigned long nr_lpids;

long kvmppc_alloc_lpid(void)
{
	long lpid;

	do {
		lpid = find_first_zero_bit(lpid_inuse, KVMPPC_NR_LPIDS);
		if (lpid >= nr_lpids) {
			pr_err("%s: No LPIDs free\n", __func__);
			return -ENOMEM;
		}
	} while (test_and_set_bit(lpid, lpid_inuse));

	return lpid;
}

void kvmppc_claim_lpid(long lpid)
{
	set_bit(lpid, lpid_inuse);
}

void kvmppc_free_lpid(long lpid)
{
	clear_bit(lpid, lpid_inuse);
}

void kvmppc_init_lpid(unsigned long nr_lpids_param)
{
	nr_lpids = min_t(unsigned long, KVMPPC_NR_LPIDS, nr_lpids_param);
	memset(lpid_inuse, 0, sizeof(lpid_inuse));
}

int kvm_arch_init(void *opaque)
{
	return 0;
}

void kvm_arch_exit(void)
{
}
