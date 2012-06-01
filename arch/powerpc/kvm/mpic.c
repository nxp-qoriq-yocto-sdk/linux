/*
 * MPIC emulation, based on Qemu code
 *
 * Only the core of the MPIC is implemented so far -- timers, IPIs, MSIs,
 * etc. aren't emulated, though they can be directly assigned from the real
 * MPIC.
 *
 * Copyright (c) 2004 Jocelyn Mayer
 * Copyright 2010-2012 Freescale Semiconductor, Inc.
 *
 * Some KVM infrastructure code is from arch/x86/kvm/i8259.c:
 *   Copyright (c) 2007 Intel Corporation
 *   Copyright 2009 Red Hat, Inc. and/or its affiliates.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/kvm_host.h>
#include <linux/errno.h>
#include <asm/mpic.h>
#include <asm/kvm_para.h>
#include <asm/kvm_host.h>
#include <asm/kvm_ppc.h>
#include "iodev.h"
#include "irq.h"

#ifdef CONFIG_KVM_E500MC
#define GUEST_CCSRBAR 0xffe000000ULL
#else
#define GUEST_CCSRBAR 0xe0000000
#endif
#define MPIC_START (GUEST_CCSRBAR + 0x40000)
#define MPIC_SIZE 0x30000

#define VECTOR_BITS 16
#define VID         0x03 /* MPIC version ID */
#define VENI        0x00000000 /* Vendor ID */

#define MPIC_EISR 0x3900
#define MPIC_EIMR 0x3910

/* Linux would enable cascaded error interrupt
 * support based on MPIC version. MPIC
 * version >= 4.1 supports EIMR which is required
 * for cascaded error interrupt handling. Also,
 * we only support error interrupts for e500mc
 * guests, so for e500v2 guests we would
 * provide an MPIC version number < 4.1.
 */
#define MPIC_BRR1_VERSION_4_1 0x00400401 /* MPIC version 4.1 */
#define MPIC_BRR1_VERSION_3_1 0x00400301 /* MPIC version 3.1 */

enum {
	IRQ_IPVP = 0,
	IRQ_IDE,
};

/* MPIC */
#define MAX_CPU      15
#define MAX_EXT      16
#define MAX_INT      240 /* Includes message and MSI interrupts */
#define MAX_TMR      8
#define MAX_IPI      4

#define MAX_ERR      32
/* MPIC interrupt 16 is the error interrupt */
#define MPIC_ERR_IRQ_NUM    16

/* Interrupt definitions */
#define MPIC_EXT_IRQ      0
#define MPIC_INT_IRQ      (MPIC_EXT_IRQ + MAX_EXT)
#define MPIC_SPECIAL_IRQ  (MPIC_INT_IRQ + MAX_INT)
#define MPIC_TMR_IRQ      MPIC_SPECIAL_IRQ
#define MPIC_IPI_IRQ      (MPIC_TMR_IRQ + MAX_TMR)
#define MPIC_ERR_IRQ      (MPIC_IPI_IRQ + MAX_IPI * MAX_CPU)
#define MAX_IRQ           (MPIC_ERR_IRQ + MAX_ERR)

struct error_int_state {
	u32 eisr;
	u32 eimr;
};

struct irq_queue {
	unsigned long queue[BITS_TO_LONGS(MAX_IRQ)];
	int next;
	int priority;
};

struct irq_source {
	struct kvm_arch_irq arch;
	uint32_t ipvp;  /* IRQ vector/priority register */
	uint32_t ide;   /* IRQ destination register */
	int type;
	int pending;    /* TRUE if IRQ is pending */
	int num;	/* IRQ number -- for bitmaps and debug messages */
};

#define IPVP_PRIORITY_MASK     (0x1F << 16)
#define IPVP_PRIORITY(_ipvpr_) ((int)(((_ipvpr_) & IPVP_PRIORITY_MASK) >> 16))
#define IPVP_VECTOR_MASK       ((1 << VECTOR_BITS) - 1)
#define IPVP_VECTOR(_ipvpr_)   ((_ipvpr_) & IPVP_VECTOR_MASK)

struct irq_dest {
	/*
	 * It's safe to assume vcpu/shared are valid in the context of MMIO
	 * emulation or paravirt iack, but check against NULL in other
	 * contexts.
	 */
	struct kvm_vcpu *vcpu;
	struct kvm_vcpu_arch_shared *shared;
	struct irq_queue raised;
	struct irq_queue servicing;
	int num;	/* vcpu number -- for debug messages */
};

#define TIMERS_PER_GROUP 4

struct openpic {
	struct kvm *kvm;

	/* Global registers */
	uint32_t frep; /* Feature reporting register */
	uint32_t glbc; /* Global configuration register  */
	uint32_t micr; /* MPIC interrupt configuration register */
	uint32_t veni; /* Vendor identification register */
	uint32_t spve; /* Spurious vector register */

	struct irq_source src[MAX_IRQ];
	struct irq_dest dst[MAX_CPU];

	struct error_int_state error_int;

	int num_cpus;
};

static int get_current_vcpuid(void)
{
	struct kvm_vcpu *vcpu = current->thread.kvm_vcpu;
	return vcpu->vcpu_id;
}

static void IRQ_setbit(struct irq_queue *q, int n_IRQ)
{
	__set_bit(n_IRQ, q->queue);
}

static void IRQ_resetbit(struct irq_queue *q, int n_IRQ)
{
	__clear_bit(n_IRQ, q->queue);
}

static void IRQ_check(struct openpic *opp, struct irq_queue *q)
{
	int next, word, irq, base;
	int priority;

	next = -1;
	priority = 0;
	for (word = 0, base = 0; word < BITS_TO_LONGS(MAX_IRQ);
	     word++, base += BITS_PER_LONG) {
		unsigned long map = q->queue[word];

		if (!map)
			continue;

		while (map) {
			int offset = __ffs(map);
			irq = base + offset;
			map &= ~(1UL << offset);

			pr_debug("IRQ_check: irq %d set ipvp_pr=%d pr=%d\n",
				 irq, IPVP_PRIORITY(opp->src[irq].ipvp),
				 priority);
			if (IPVP_PRIORITY(opp->src[irq].ipvp) > priority) {
				next = irq;
				priority = IPVP_PRIORITY(opp->src[irq].ipvp);
			}
		}
	}

	q->next = next;
	q->priority = priority;
}

static int IRQ_get_next(struct openpic *opp, struct irq_queue *q)
{
	IRQ_check(opp, q);

	return q->next;
}

static void mpic_irq_raise(struct openpic *mpp, struct irq_dest *dst)
{
	struct kvm_interrupt irq = {
		.irq = KVM_INTERRUPT_SET_LEVEL,
	};

	pr_debug("%s: cpu %d\n", __func__, dst->num);

	if (dst->vcpu)
		kvm_vcpu_ioctl_interrupt(dst->vcpu, &irq);
}

static void mpic_irq_lower(struct openpic *mpp, struct irq_dest *dst)
{
	struct kvm_interrupt irq = {
		.irq = KVM_INTERRUPT_UNSET,
	};

	pr_debug("%s: cpu %d\n", __func__, dst->num);

	if (dst->vcpu)
		kvmppc_core_dequeue_external(dst->vcpu, &irq);
}

/*
 * Call after modifying and checking raised or servicing,
 * but before reading mpic_ctpr.  Caller must ensure that
 * dst->shared is non-NULL.
 */
static void update_prio_pending(struct irq_dest *dst)
{
	/*
	 * Don't make the guest trap when lowering CTPR, if an interrupt
	 * already in service would mean no new interrupt would be
	 * delivered.
	 */
	if (dst->raised.priority > dst->servicing.priority)
		dst->shared->mpic_prio_pending = dst->raised.priority;
	else
		dst->shared->mpic_prio_pending = 0;

	/*
	 * The vcpu may be running on another CPU, which may be
	 * lowering CTPR -- make sure that either the vcpu sees the
	 * new prio_pending, or that our caller sees the new ctpr.
	 */
	smp_mb();
}

static void IRQ_local_pipe(struct openpic *opp, int n_CPU,
			   struct irq_source *src, int active)
{
	struct irq_dest *dst;
	int priority;

	dst = &opp->dst[n_CPU];
	if (!dst->shared)
		return;

	priority = IPVP_PRIORITY(src->ipvp);

	/*
	 * Even if the interrupt doesn't have enough priority,
	 * it is still raised, in case CTPR is lowered later.
	 */
	if (active)
		IRQ_setbit(&dst->raised, src->num);
	else
		IRQ_resetbit(&dst->raised, src->num);

	IRQ_check(opp, &dst->raised);
	update_prio_pending(dst);

	if (active && priority <= dst->shared->mpic_ctpr) {
		pr_debug("%s: IRQ %d priority %d too low for CTPR %d on CPU %d\n",
			 __func__, src->num, priority, dst->shared->mpic_ctpr, n_CPU);
		active = 0;
	}

	/* TODO critical ints */
	if (active) {
		if (IRQ_get_next(opp, &dst->servicing) >= 0 &&
		    priority <= dst->servicing.priority) {
			pr_debug("%s: IRQ %d is hidden by servicing IRQ %d on CPU %d\n",
				 __func__, src->num, dst->servicing.next, n_CPU);
			/* Already servicing a higher/same priority IRQ */
		} else {
			pr_debug("%s: raising IRQ %d cpu %d\n",
				 __func__, src->num, n_CPU);
			mpic_irq_raise(opp, dst);
		}
	} else {
		if (dst->raised.priority > dst->shared->mpic_ctpr &&
		    dst->raised.priority > dst->servicing.priority) {
			pr_debug("%s: prio %d raised on cpu %d above ctpr %d\n",
				 __func__, dst->raised.priority,
				 n_CPU, dst->shared->mpic_ctpr);
			/* IRQ line stays asserted */
		} else {
			pr_debug("%s: no IRQ on cpu %d above prio %d\n",
				 __func__, n_CPU, dst->shared->mpic_ctpr);
			mpic_irq_lower(opp, dst);
		}
	}
}

/* update pic state because IRQ registers have changed value */
static void openpic_update_irq(struct openpic *opp, struct irq_source *src)
{
	int i;
	int active = src->pending;

	if (active && (src->ipvp & MPIC_VECPRI_MASK)) {
		/* Interrupt source is disabled */
		pr_debug("%s: IRQ %d is disabled\n", __func__, src->num);
		active = 0;
	}

	/*
	 * We don't have a similar check for already-active because
	 * CTPR may have changed and we need to withdraw the interrupt.
	 */
	if (!active && !(src->ipvp & MPIC_VECPRI_ACTIVITY)) {
		pr_debug("%s: IRQ %d is already inactive\n",
			 __func__, src->num);
		return;
	}

	if (active)
		src->ipvp |= MPIC_VECPRI_ACTIVITY;
	else
		src->ipvp &= ~MPIC_VECPRI_ACTIVITY;

	/* Directed delivery mode */
	for (i = 0; i < opp->num_cpus; i++) {
		if (src->ide & (1 << i))
			IRQ_local_pipe(opp, i, src, active);
	}
}

static void openpic_set_irq(struct openpic *opp, struct irq_source *src,
			    int level)
{
	pr_debug("openpic: set irq %d = %d ipvp=%08x\n",
		 src->num, level, src->ipvp);
	if (src->ipvp & MPIC_VECPRI_SENSE_LEVEL) {
		/* level-sensitive irq */
		src->pending = level;
	} else {
		/* edge-sensitive irq */
		if (level)
			src->pending = 1;
	}
	openpic_update_irq(opp, src);
}

static void openpic_set_err_int(struct openpic *opp)
{
	struct irq_source *src = &opp->src[MPIC_ERR_IRQ_NUM];
	int level = 1;

	if (!(opp->error_int.eisr & ~opp->error_int.eimr))
		level = 0;

	openpic_set_irq(opp, src, level);
}

static inline int mpic_is_err_int_src(struct irq_source *src)
{
#ifdef CONFIG_KVM_E500MC
	return src->num >= MPIC_ERR_IRQ && src->num < MPIC_ERR_IRQ + MAX_ERR;
#else
	return 0;
#endif
}

static inline int mpic_is_ipi_src(struct irq_source *src)
{
	return src->num >= MPIC_IPI_IRQ && src->num < MPIC_ERR_IRQ;
}

static void openpic_handle_error_irq(struct openpic *opp, struct irq_source *src, int level)
{
	int err_int = src->num - MPIC_ERR_IRQ;
	u32 err_int_mask;

	err_int_mask = 1 << (31 - err_int);

	if (!level)
		opp->error_int.eisr &= ~err_int_mask;
	else
		opp->error_int.eisr |=  err_int_mask;

	openpic_set_err_int(opp);
}

static uint32_t read_IRQreg(struct openpic *opp, int n_IRQ, uint32_t reg)
{
	uint32_t retval;

	switch (reg) {
	case IRQ_IPVP:
		retval = opp->src[n_IRQ].ipvp;
		break;
	case IRQ_IDE:
		retval = opp->src[n_IRQ].ide;
		break;
	}

	return retval;
}

static void write_IRQreg(struct openpic *opp, int n_IRQ,
			 uint32_t reg, uint32_t val)
{
	uint32_t tmp;
	struct irq_source *src = &opp->src[n_IRQ];

	switch (reg) {
	case IRQ_IPVP:
		/*
		 * NOTE: not fully accurate for special IRQs, but simple and
		 * sufficient.
		 *
		 * Should technically treat internal interrupts differently
		 * on Freescale MPICs -- polarity should be read-only and
		 * always on, sense bit is reserved but effectively always
		 * on.
		 */
		/* ACTIVITY bit is read-only */
		src->ipvp = (src->ipvp & MPIC_VECPRI_ACTIVITY) |
			    (val & 0x80CF00FF);
		openpic_update_irq(opp, src);
		pr_debug("Set IPVP %d to 0x%08x -> 0x%08x\n",
			 n_IRQ, val, src->ipvp);
		break;
	case IRQ_IDE:
		tmp = val & 0xC0000000;
		tmp |= val & ((1 << opp->num_cpus) - 1);
		src->ide = tmp;
		pr_debug("Set IDE %d to 0x%08x\n", n_IRQ, src->ide);
		break;
	}
}

static void mpic_reset_cpu(struct openpic *mpp, struct kvm_vcpu *vcpu)
{
	int i = vcpu->vcpu_id;

	mpp->dst[i].shared->mpic_ctpr = 15;
	mpp->dst[i].shared->mpic_prio_pending = 0;
	memset(&mpp->dst[i].raised, 0, sizeof(struct irq_queue));
	mpp->dst[i].raised.next = -1;
	memset(&mpp->dst[i].servicing, 0, sizeof(struct irq_queue));
	mpp->dst[i].servicing.next = -1;
}

static void mpic_reset(struct openpic *mpp)
{
	struct kvm_vcpu *vcpu;
	int i;

	/* Initialise controller registers */
	mpp->frep = (MAX_IRQ << 16) | 2 | ((MAX_CPU - 1) << 8);
	mpp->veni = 0x00000000;
	mpp->spve = 0x0000FFFF;
	/* Initialise IRQ sources */
	for (i = 0; i < MAX_IRQ; i++) {
		mpp->src[i].ipvp = 0x80800000;
		mpp->src[i].ide  = 0x00000001;
		mpp->src[i].num  = i;
	}

	/*
	 * We use IDE of IPIs to track which CPUs have pending IPIs.
	 * So set IDE for IPIs to 0 so we don't get spurious interrupts.
	 */
	for (i = MPIC_IPI_IRQ; i < (MPIC_IPI_IRQ + MAX_IPI); i++)
		mpp->src[i].ide = 0;

	kvm_for_each_vcpu(i, vcpu, mpp->kvm)
		mpic_reset_cpu(mpp, vcpu);
}

static int openpic_gbl_write(struct kvm_pic *pic, int addr, uint32_t val)
{
	struct openpic *opp = pic->priv;

	pr_debug("%s: addr %08x <= %08x\n", __func__, addr, val);
	if (addr & 0xF)
		return -EOPNOTSUPP;
	addr &= 0xFF;

	switch (addr) {
	case 0x00: /* FREP */
		break;
	case 0x20: /* GLBC */
		if (val & 0x80000000)
			mpic_reset(opp);
		opp->glbc = val & ~0x80000000;

		/* reset both the in-kernel and qemu MPICs */
		return -EOPNOTSUPP;
	case 0x80: /* VENI */
		break;
	case 0x90: /* PINT */
		/* We're not going to deal with CPU reset here.
		 * Let Qemu deal with it.
		 */
		return -EOPNOTSUPP;
	case 0xA0: /* IPI_IPVP */
	case 0xB0:
	case 0xC0:
	case 0xD0: {
		int idx;
		idx = (addr - 0xA0) >> 4;
		/* Clear unvalid bits for IPI_IPVR */
		val &= MPIC_VECPRI_MASK | MPIC_VECPRI_ACTIVITY |
		       MPIC_VECPRI_PRIORITY_MASK | MPIC_VECPRI_VECTOR_MASK;
		write_IRQreg(opp, MPIC_IPI_IRQ + idx, IRQ_IPVP, val);

		break;
	}
	case 0xE0: /* SPVE */
		opp->spve = val & 0x0000FFFF;
		break;
	default:
		return -EOPNOTSUPP;
	}

	return 0;
}

static int openpic_gbl_read(struct kvm_pic *pic, int addr, uint32_t *val)
{
	struct openpic *opp = pic->priv;
	uint32_t retval;

	pr_debug("%s: addr %08x\n", __func__, addr);
	retval = 0xFFFFFFFF;
	if (addr & 0xF)
		goto err;
	addr &= 0xFF;

	switch (addr) {
	case 0x00: /* FREP */
		retval = opp->frep;
		break;
	case 0x20: /* GLBC */
		retval = opp->glbc;
		break;
	case 0x80: /* VENI */
		retval = opp->veni;
		break;
	case 0x90: /* PINT */
		retval = 0x00000000;
		break;
	case 0xA0: /* IPI_IPVP */
	case 0xB0:
	case 0xC0:
	case 0xD0: {
		int idx;
		idx = (addr - 0xA0) >> 4;
		retval = read_IRQreg(opp, MPIC_IPI_IRQ + idx, IRQ_IPVP);

		break;
	}
	case 0xE0: /* SPVE */
		retval = opp->spve;
		break;
	default:
		goto err;
	}

	pr_debug("%s: => %08x\n", __func__, retval);
	*val = retval;
	return 0;

err:
	pr_debug("%s: => unhandled\n", __func__);
	return -EOPNOTSUPP;
}

static int mpic_timer_write(struct kvm_pic *pic, int addr, uint32_t val)
{
	struct openpic *mpp = pic->priv;
	int idx;

	pr_debug("%s: addr %08x <= %08x\n", __func__, addr, val);
	if (addr & 0xF)
		return -EOPNOTSUPP;
	addr &= 0xFFFF;

	if (addr < 0x1100 ||
	    (addr >= 0x1200 && addr < 0x2100) ||
	    addr >= 0x2200)
		return -EOPNOTSUPP;

	idx = (addr >> 6) & 3;
	idx |= (addr >> 11) & 4;

	switch (addr & 0x30) {
	case 0x00: /* gtccr */
	case 0x10: /* gtbcr */
		return -EOPNOTSUPP;
	case 0x20: /* GTIVPR */
		write_IRQreg(mpp, MPIC_TMR_IRQ + idx, IRQ_IPVP, val);
		break;
	case 0x30: /* GTIDR */
		write_IRQreg(mpp, MPIC_TMR_IRQ + idx, IRQ_IDE, val);
		break;
	}

	return 0;
}

static int mpic_timer_read(struct kvm_pic *pic, int addr, uint32_t *val)
{
	struct openpic *mpp = pic->priv;
	uint32_t retval;
	int idx;

	pr_debug("%s: addr %08x\n", __func__, addr);
	retval = 0xFFFFFFFF;
	if (addr & 0xF)
		goto err;
	addr &= 0xFFFF;

	if (addr < 0x1100 ||
	    (addr >= 0x1200 && addr < 0x2100) ||
	    addr >= 0x2200)
		goto err;

	idx = (addr >> 6) & 3;
	idx |= (addr >> 11) & 4;

	switch (addr & 0x30) {
	case 0x00: /* gtccr */
	case 0x10: /* gtbcr */
		goto err;
	case 0x20: /* TIPV */
		retval = read_IRQreg(mpp, MPIC_TMR_IRQ + idx, IRQ_IPVP);
		break;
	case 0x30: /* TIDR */
		retval = read_IRQreg(mpp, MPIC_TMR_IRQ + idx, IRQ_IDE);
		break;
	}
	pr_debug("%s: => %08x\n", __func__, retval);

	*val = retval;
	return 0;

err:
	pr_debug("%s: => unhandled\n", __func__);
	return -EOPNOTSUPP;
}

static int openpic_src_write(struct kvm_pic *pic, uint32_t addr, uint32_t val)
{
	struct openpic *opp = pic->priv;
	int idx;

	pr_debug("%s: addr %08x <= %08x\n", __func__, addr, val);
	if (addr & 0xF)
		return -EOPNOTSUPP;
	addr = addr & 0xFFF0;
	idx = addr >> 5;
	if (addr & 0x10) {
		/* EXDE / IFEDE / IEEDE */
		write_IRQreg(opp, idx, IRQ_IDE, val);
	} else {
		/* EXVP / IFEVP / IEEVP */
		write_IRQreg(opp, idx, IRQ_IPVP, val);
	}

	return 0;
}

static int openpic_src_read(struct kvm_pic *pic, uint32_t addr,
			    uint32_t *val)
{
	struct openpic *opp = pic->priv;
	uint32_t retval;
	int idx;

	pr_debug("%s: addr %08x\n", __func__, addr);
	retval = 0xFFFFFFFF;
	if (addr & 0xF)
		goto err;
	addr = addr & 0xFFF0;
	idx = addr >> 5;
	if (addr & 0x10) {
		/* EXDE / IFEDE / IEEDE */
		retval = read_IRQreg(opp, idx, IRQ_IDE);
	} else {
		/* EXVP / IFEVP / IEEVP */
		retval = read_IRQreg(opp, idx, IRQ_IPVP);
	}
	pr_debug("%s: => %08x\n", __func__, retval);
	*val = retval;

	return 0;

err:
	pr_debug("%s: => unhandled\n", __func__);
	return -EOPNOTSUPP;
}

#ifdef CONFIG_KVM_E500MC
static void openpic_notify_acked_errirq(struct openpic *opp)
{
	u32 eisr = opp->error_int.eisr;
	int index, err_int;

	while (eisr) {
		index = __ffs(eisr);
		err_int = MPIC_ERR_IRQ + (31 - index);
		kvm_notify_acked_sysirq(opp->kvm, &opp->src[err_int].arch);
		eisr &= ~(1 << index);
	}
}
#endif

static int openpic_cpu_write(struct kvm_pic *pic, int addr, uint32_t val)
{
	struct openpic *opp = pic->priv;
	struct irq_source *src;
	struct irq_dest *dst;
	int idx, s_IRQ, n_IRQ;

	pr_debug("%s: addr %08x <= %08x\n", __func__, addr, val);
	if (addr & 0xF)
		return -EOPNOTSUPP;

	if (addr >= 0x20000) {
		addr &= 0x1FFF0;
		idx = addr / 0x1000;
	} else {
		idx = get_current_vcpuid();
	}

	dst = &opp->dst[idx];
	addr &= 0xFF0;

	switch (addr) {
	case 0x40:
	case 0x50:
	case 0x60:
	case 0x70:
		idx = (addr - 0x40) >> 4;
		/* Save pending IPIs to wchich CPUs in IDE */
		val = read_IRQreg(opp, MPIC_IPI_IRQ + idx, IRQ_IDE) | val;
		write_IRQreg(opp, MPIC_IPI_IRQ + idx, IRQ_IDE, val);
		openpic_set_irq(opp, &opp->src[MPIC_IPI_IRQ + idx], 1);

		break;
	case 0x80: /* PCTP */
		dst->shared->mpic_ctpr = val & 0x0000000F;

		pr_debug("%s: set cpu %d CTPR to %d, raised %d servicing %d\n",
			 __func__, idx, dst->shared->mpic_ctpr, dst->raised.priority,
			 dst->servicing.priority);

		if (dst->raised.priority <= dst->shared->mpic_ctpr)
			mpic_irq_lower(opp, dst);
		else if (dst->raised.priority > dst->servicing.priority)
			mpic_irq_raise(opp, dst);

		break;
	case 0x90: /* WHOAMI */
		/* Read-only register */
		break;
	case 0xA0: /* PIAC */
		/* Read-only register */
		break;
	case 0xB0: /* PEOI */
		pr_debug("PEOI\n");
		s_IRQ = IRQ_get_next(opp, &dst->servicing);

		if (s_IRQ < 0) {
			pr_debug("%s: EOI with no in-service interrupt\n",
				 __func__);
			break;
		}

		IRQ_resetbit(&dst->servicing, s_IRQ);

		/* Set up next servicing IRQ */
		IRQ_check(opp, &dst->servicing);
		/* Check queued interrupts. */
		n_IRQ = IRQ_get_next(opp, &dst->raised);
		update_prio_pending(dst);

		src = &opp->src[n_IRQ];
		if (dst->raised.priority > dst->shared->mpic_ctpr &&
		    dst->raised.priority > dst->servicing.priority) {
			pr_debug("Raise OpenPIC INT output cpu %d irq %d\n",
				 idx, n_IRQ);
			mpic_irq_raise(opp, dst);
		}

		/*
		 * We are dropping lock while calling ack notifiers since
		 * ack notifier callbacks for assigned devices call into PIC
		 * recursively.  Other interrupt may be delivered to PIC
		 * while lock is dropped but it should be safe since
		 * state is already updated at this stage.
		 */
		spin_unlock(&pic->lock);
#ifdef CONFIG_KVM_E500MC
		if (s_IRQ == MPIC_ERR_IRQ_NUM)
			openpic_notify_acked_errirq(opp);
		else
#endif
			kvm_notify_acked_sysirq(opp->kvm, &opp->src[s_IRQ].arch);
		spin_lock(&pic->lock);

		break;
	default:
		return -EOPNOTSUPP;
	}

	return 0;
}

static u32 iack_nolock(struct openpic *opp, struct irq_dest *dst)
{
	struct irq_source *src;
	u32 retval;
	int n_IRQ, irq_in_service;

	pr_debug("Lower OpenPIC INT output\n");
	mpic_irq_lower(opp, dst);

	irq_in_service = IRQ_get_next(opp, &dst->servicing);
	n_IRQ = IRQ_get_next(opp, &dst->raised);

	if (irq_in_service >= 0 &&
	    dst->raised.priority <= dst->servicing.priority) {
		/*
		 * Interrupt already in service and no higher
		 * prio interrupt pending -- return it again
		 */
		n_IRQ = irq_in_service;
	}


	pr_debug("PIAC: irq=%d\n", n_IRQ);
	if (n_IRQ < 0) {
		/* No more interrupt pending */
		return IPVP_VECTOR(opp->spve);
	}

	src = &opp->src[n_IRQ];
	if (!(src->ipvp & MPIC_VECPRI_ACTIVITY) ||
	    !(IPVP_PRIORITY(src->ipvp) > dst->shared->mpic_ctpr)) {
		/* Can happen with CTPR paravirt, see kvm_para.h */
		pr_debug("%s: bad raised IRQ %d ctpr %d ipvp %#x\n",
			 __func__, n_IRQ, dst->shared->mpic_ctpr, src->ipvp);
		return IPVP_VECTOR(opp->spve);
	}

	/* IRQ enter servicing state */
	IRQ_setbit(&dst->servicing, n_IRQ);
	IRQ_check(opp, &dst->servicing);

	retval = IPVP_VECTOR(src->ipvp);

	IRQ_resetbit(&dst->raised, n_IRQ);
	IRQ_check(opp, &dst->raised);

	if (!(src->ipvp & MPIC_VECPRI_SENSE_LEVEL)) {
		/* edge-sensitive IRQ */
		int clear_pending = 1;

		if ((n_IRQ >= MPIC_IPI_IRQ) &&
		    (n_IRQ < (MPIC_IPI_IRQ + MAX_IPI))) {
			src->ide &= ~(1 << dst->vcpu->vcpu_id);
			if (src->ide)
				clear_pending = 0;
		}

		if (clear_pending) {
			pr_debug("lowering edge %d\n", n_IRQ);
			src->ipvp &= ~MPIC_VECPRI_ACTIVITY;
			src->pending = 0;
		}
	}

	update_prio_pending(dst);
	return retval;
}

int kvm_mpic_is_using_coreint(struct kvm *kvm)
{
	struct openpic *opp = kvm->arch.vpic->priv;
	return	opp->glbc & 0x60000000;
}

u32 kvmppc_mpic_iack(struct kvm *kvm, int vcpu)
{
	struct kvm_pic *pic = kvm->arch.vpic;
	struct openpic *priv;
	unsigned long flags;
	u32 retval;

	if (!pic)
		return 0xffff;

	priv  = pic->priv;

	if (vcpu >= MAX_CPU)
		return -EINVAL;

	spin_lock_irqsave(&pic->lock, flags);
	retval = iack_nolock(priv, &priv->dst[vcpu]);
	spin_unlock_irqrestore(&pic->lock, flags);

	return retval;
}

static uint32_t openpic_cpu_read(struct kvm_pic *pic, int addr, u32 *valp)
{
	struct openpic *opp = pic->priv;
	struct irq_dest *dst;
	uint32_t retval;
	int idx;

	pr_debug("%s: addr %08x\n", __func__, addr);
	retval = 0xFFFFFFFF;
	if (addr & 0xF)
		goto err;

	if (addr >= 0x20000) {
		addr &= 0x1FFF0;
		idx = addr / 0x1000;
	} else {
		idx = get_current_vcpuid();
	}

	dst = &opp->dst[idx];
	addr &= 0xFF0;

	switch (addr) {
	case 0x0: /* BRR1 */
#ifdef CONFIG_KVM_E500MC
		retval = MPIC_BRR1_VERSION_4_1;
#else
		retval = MPIC_BRR1_VERSION_3_1;
#endif
		break;
	case 0x80: /* PCTP */
		retval = dst->shared->mpic_ctpr;
		break;
	case 0x90: /* WHOAMI */
		retval = idx;
		break;
	case 0xA0: /* PIAC */
		retval = iack_nolock(opp, dst);
		break;
	case 0xB0: /* PEOI */
		retval = 0;
		break;
	default:
		goto err;
	}
	pr_debug("%s: => %08x\n", __func__, retval);
	*valp = retval;

	return 0;

err:
	pr_debug("%s: => unhandled\n", __func__);
	return -EOPNOTSUPP;
}

static uint32_t mpic_err_write(struct kvm_pic *pic, int addr, u32 val)
{
	struct openpic *opp = pic->priv;

	pr_debug("%s: addr %08x\n", __func__, addr);

	if (addr != MPIC_EIMR) {
		pr_debug("%s: => unhandled\n", __func__);
		return -EOPNOTSUPP;
	}

	opp->error_int.eimr = val;

	openpic_set_err_int(opp);

	return 0;
}

static uint32_t mpic_err_read(struct kvm_pic *pic, int addr, u32 *valp)
{
	struct openpic *opp = pic->priv;

	pr_debug("%s: addr %08x\n", __func__, addr);

	switch (addr) {
	case MPIC_EISR:
		*valp = opp->error_int.eisr & ~opp->error_int.eimr;
		return 0;
	case MPIC_EIMR:
		*valp = opp->error_int.eimr;
		return 0;
	default:
		pr_debug("%s: => unhandled\n", __func__);
		return -EOPNOTSUPP;
	}
}

static int openpic_writel(struct kvm_pic *pic, int addr, uint32_t val)
{
	int ret = 0;

	pr_debug("%s: offset %08x val: %08x\n", __func__, addr, val);
	if (addr < 0x1000) {
		/* CPU registers */
		ret = openpic_cpu_write(pic, addr, val);
	} else if (addr < 0x10f0) {
		/* Global registers */
		ret = openpic_gbl_write(pic, addr, val);
	} else if (addr < 0x2400) {
		/* Timers registers */
		ret = mpic_timer_write(pic, addr, val);
	} else if (addr < 0x3a00) {
		/* Error Interrupt registers */
		ret = mpic_err_write(pic, addr, val);
	} else if (addr < 0x20000) {
		/* Source registers */
		ret = openpic_src_write(pic, addr, val);
	} else {
		/* CPU registers */
		ret = openpic_cpu_write(pic, addr, val);
	}

	return ret;
}

static int openpic_readl(struct kvm_pic *pic, int addr, u32 *val)
{
	int ret = 0;

	pr_debug("%s: offset %08x\n",  __func__, addr);

	if (addr < 0x1000) {
		/* CPU registers */
		ret = openpic_cpu_read(pic, addr, val);
	} else if (addr < 0x10f0) {
		/* Global registers */
		ret = openpic_gbl_read(pic, addr, val);
	} else if (addr < 0x2400) {
		/* Timers registers */
		ret = mpic_timer_read(pic, addr, val);
	} else if (addr < 0x3a00) {
		/* Error Interrupt registers */
		ret = mpic_err_read(pic, addr, val);
	} else if (addr < 0x20000) {
		/* Source registers */
		ret = openpic_src_read(pic, addr, val);
	} else {
		/* CPU registers */
		ret = openpic_cpu_read(pic, addr, val);
	}

	return ret;
}

static struct kvm_pic *to_pic(struct kvm_io_device *dev)
{
	return container_of(dev, struct kvm_pic, dev);
}

static int kvm_mpic_in_range(gpa_t addr)
{
	return addr >= MPIC_START && addr < MPIC_START + MPIC_SIZE;
}

static int kvm_mpic_write(struct kvm_io_device *this,
			  gpa_t addr, int len, const void *val)
{
	struct kvm_pic *s = to_pic(this);
	u32 data;
	int ret;

	if (!kvm_mpic_in_range(addr))
		return -EOPNOTSUPP;

	addr -= MPIC_START;

	if (len != 4) {
		if (printk_ratelimit())
			printk(KERN_ERR "KVM MPIC: non word write\n");
		return 0;
	}

	data = *(u32 *)val;

	spin_lock_irq(&s->lock);
	ret = openpic_writel(s, addr, *(uint32_t *)val);
	spin_unlock_irq(&s->lock);

	return ret;
}

static int kvm_mpic_read(struct kvm_io_device *this,
			 gpa_t addr, int len, void *val)
{
	struct kvm_pic *s = to_pic(this);
	int ret;

	if (!kvm_mpic_in_range(addr))
		return -EOPNOTSUPP;

	addr -= MPIC_START;

	if (len != 4) {
		if (printk_ratelimit())
			printk(KERN_ERR "PIC: non word read\n");
		return 0;
	}

	spin_lock_irq(&s->lock);
	ret = openpic_readl(s, addr, val);
	spin_unlock_irq(&s->lock);

	return ret;
}

int kvm_arch_irqchip_add_vcpu(struct kvm_vcpu *vcpu)
{
	struct kvm_pic *pic = vcpu->kvm->arch.vpic;
	struct openpic *priv;
	unsigned long flags;

	if (!pic)
		return 0;
	if (vcpu->vcpu_id >= MAX_CPU)
		return -EINVAL;

	priv = pic->priv;

	spin_lock_irqsave(&pic->lock, flags);

	priv->dst[vcpu->vcpu_id].vcpu = vcpu;
	priv->dst[vcpu->vcpu_id].shared = vcpu->arch.shared;
	priv->num_cpus++;
	mpic_reset_cpu(priv, vcpu);

	spin_unlock_irqrestore(&pic->lock, flags);
	return 0;
}

void kvm_arch_irqchip_remove_vcpu(struct kvm_vcpu *vcpu)
{
	struct kvm_pic *pic = vcpu->kvm->arch.vpic;
	struct openpic *priv;
	unsigned long flags;

	if (!pic)
		return;
	if (vcpu->vcpu_id >= MAX_CPU)
		return;

	priv = pic->priv;

	spin_lock_irqsave(&pic->lock, flags);

	priv->dst[vcpu->vcpu_id].vcpu = NULL;
	priv->dst[vcpu->vcpu_id].shared = NULL;

	spin_unlock_irqrestore(&pic->lock, flags);
}

static const struct kvm_io_device_ops picdev_ops = {
	.read = kvm_mpic_read,
	.write = kvm_mpic_write,
};

struct kvm_pic *kvm_create_pic(struct kvm *kvm)
{
	struct kvm_pic *s;
	struct openpic *priv;
	int ret;

	s = kzalloc(sizeof(struct kvm_pic), GFP_KERNEL);
	if (!s)
		return NULL;

	s->priv = priv = kzalloc(sizeof(struct openpic), GFP_KERNEL);
	if (!priv)
		goto out;

	priv->num_cpus = 0;
	priv->kvm = kvm;

	mpic_reset(priv);

	spin_lock_init(&s->lock);

	/*
	 * Initialize MMIO device
	 */
	kvm_iodevice_init(&s->dev, &picdev_ops);
	mutex_lock(&kvm->slots_lock);
	ret = kvm_io_bus_register_dev(kvm, KVM_MMIO_BUS, &s->dev);
	mutex_unlock(&kvm->slots_lock);
	if (ret < 0)
		goto out_priv;

	return s;

out_priv:
	kfree(priv);
out:
	kfree(s);
	return NULL;
}

int kvm_arch_set_irq(struct kvm *kvm, struct kvm_arch_irq *irq, int level)
{
	struct kvm_pic *pic = kvm->arch.vpic;
	struct openpic *priv = pic->priv;
	struct irq_source *src = container_of(irq, struct irq_source, arch);
	unsigned long flags;

	spin_lock_irqsave(&pic->lock, flags);

	/*
	* Emulated IPIs are triggered by setting the destination
	* field, use the same approach for IPIs that are triggered
	* from a direct mapped IPI interrupt.
	*/
	if (mpic_is_ipi_src(src))
		src->ide = 0x1;

	if (mpic_is_err_int_src(src))
		openpic_handle_error_irq(priv, src, level);
	else
		openpic_set_irq(priv, src, level);

	spin_unlock_irqrestore(&pic->lock, flags);
	return 1;
}

int kvm_arch_set_irqnum(struct kvm *kvm, u32 irq, int level)
{
	struct kvm_pic *pic = kvm->arch.vpic;
	struct openpic *priv = pic->priv;
	unsigned long flags;

	if (irq >= MPIC_SPECIAL_IRQ)
		return -EINVAL;

	spin_lock_irqsave(&pic->lock, flags);
	openpic_set_irq(priv, &priv->src[irq], level);
	spin_unlock_irqrestore(&pic->lock, flags);
	return 1;
}

struct kvm_arch_irq *
kvm_arch_lookup_irq(struct kvm *kvm, struct kvm_assigned_irq *irq)
{
	struct kvm_pic *pic = kvm->arch.vpic;
	struct openpic *priv = pic->priv;
	u32 irqnum;

	if (irq->flags & KVM_SYSIRQ_DEVTREE_INTSPEC) {
		if (irq->sysirq.intspec_len == 2) {
			irqnum = irq->sysirq.intspec[0];

			if (irqnum >= MPIC_SPECIAL_IRQ)
				return NULL;

			return &priv->src[irqnum].arch;
		}

		if (irq->sysirq.intspec_len != 4) {
			pr_debug("%s: invalid intspec_len %u\n",
				 __func__, irq->sysirq.intspec_len);
			return NULL;
		}

		switch (irq->sysirq.intspec[2]) {
		case 0:
			irqnum = irq->sysirq.intspec[0];

			if (irqnum >= MPIC_SPECIAL_IRQ)
				return NULL;

			return &priv->src[irqnum].arch;
#ifdef CONFIG_KVM_E500MC
		case 1: /* Error Interrupts */
			irqnum = irq->sysirq.intspec[3];
			if (irqnum >= MAX_ERR)
				return NULL;
			return &priv->src[irqnum + MPIC_ERR_IRQ].arch;
#endif
		case 2: /* IPIs */
			irqnum = irq->sysirq.intspec[0];
			if (irqnum >= MAX_IPI)
				return NULL;

			return &priv->src[irqnum + MPIC_IPI_IRQ].arch;

		case 3: /* timers */
			irqnum = irq->sysirq.intspec[0];
			if (irqnum >= MAX_TMR)
				return NULL;

			return &priv->src[irqnum + MPIC_TMR_IRQ].arch;

		default:
			pr_debug("%s: invalid unknown irq type %u\n",
				 __func__, irq->sysirq.intspec[2]);
			return NULL;
		}
	}

	irqnum = irq->guest_irq;
	if (irqnum >= MPIC_SPECIAL_IRQ)
		return NULL;

	return &priv->src[irqnum].arch;
}
