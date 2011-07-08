/*
 * Kernel-based Virtual Machine
 * non-PCI IRQ assignment support without PC dependencies
 *
 * Copyright 2010-2011 Freescale Semiconductor, Inc.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */
#ifndef KVM_IRQ_H
#define KVM_IRQ_H

#include <linux/spinlock.h>
#include "iodev.h"

#define KVM_NR_IRQCHIPS 1

#ifdef CONFIG_KVM_MPIC
static inline int irqchip_in_kernel(struct kvm *kvm)
{
	return kvm->arch.vpic != NULL;

}

int kvm_arch_irqchip_add_vcpu(struct kvm_vcpu *vcpu);
void kvm_arch_irqchip_remove_vcpu(struct kvm_vcpu *vcpu);
#else
static inline int irqchip_in_kernel(struct kvm *kvm)
{
	return 0;

}

static inline int kvm_arch_irqchip_add_vcpu(struct kvm_vcpu *vcpu)
{
	return 0;
}

static inline void kvm_arch_irqchip_remove_vcpu(struct kvm_vcpu *vcpu)
{
}
#endif

struct kvm_arch_irq {
	struct kvm_assigned_dev_kernel *dev;
};

struct kvm_pic {
	struct kvm_io_device dev;
	spinlock_t lock;
	void *priv;
};

struct kvm_pic *kvm_create_pic(struct kvm *kvm);
#endif

int kvm_vcpu_ioctl_interrupt(struct kvm_vcpu *vcpu, struct kvm_interrupt *irq);
int kvm_arch_set_irqnum(struct kvm *kvm, u32 irq, int level);
