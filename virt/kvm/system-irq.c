 /*
 * Kernel-based Virtual Machine
 * non-PCI IRQ assignment support without PC dependencies
 *
 * This is mutually exclusive with, and based on, assigned-dev.c/irq_comm.c
 *
 * TODO: refactor a common base with the PCI/APIC/etc. stuff
 *
 * Copyright (C) 2010 Red Hat, Inc. and/or its affiliates.
 * Copyright 2010,2011 Freescale Semiconductor, Inc.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include <linux/uaccess.h>
#include <linux/errno.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/of.h>
#include "irq.h"

static DEFINE_SPINLOCK(irq_to_dev_lock);

static struct kvm_assigned_dev_kernel *
kvm_find_system_irq(struct list_head *head, int host_irq)
{
	struct list_head *ptr;
	struct kvm_assigned_dev_kernel *match;

	list_for_each(ptr, head) {
		match = list_entry(ptr, struct kvm_assigned_dev_kernel, list);
		if (match->host_irq == host_irq)
			return match;
	}
	return NULL;
}

static irqreturn_t kvm_assigned_dev_intr(int irq, void *dev_id)
{
	unsigned long flags;
	struct kvm_assigned_dev_kernel *dev =
		(struct kvm_assigned_dev_kernel *) dev_id;

	spin_lock_irqsave(&dev->intx_lock, flags);
	kvm_arch_set_irq(dev->kvm, dev->guest_arch_irq, 1);

	disable_irq_nosync(irq);
	dev->host_irq_disabled = true;

	spin_unlock_irqrestore(&dev->intx_lock, flags);
	return IRQ_HANDLED;
}

void kvm_notify_acked_sysirq(struct kvm *kvm, struct kvm_arch_irq *irq)
{
	struct kvm_assigned_dev_kernel *dev;
	unsigned long flags;

	spin_lock_irqsave(&irq_to_dev_lock, flags);
	dev = irq->dev;
	if (dev) {
		/* For level triggered interrupts, we don't want the
		 * emulated irqchip to automatically reraise -- if it's
		 * still active, the hardware will fire again.
		 *
		 * For edge triggered interrupts, this should be a no-op.
		 */
		kvm_arch_set_irq(kvm, irq, 0);

		/* Be robust against duplicate ACKs from the guest */
		spin_lock(&dev->intx_lock);
		if (dev->host_irq_disabled) {
			enable_irq(dev->host_irq);
			dev->host_irq_disabled = false;
		}
		spin_unlock(&dev->intx_lock);
	}
	spin_unlock_irqrestore(&irq_to_dev_lock, flags);
}

static void deassign_guest_irq(struct kvm *kvm,
			       struct kvm_assigned_dev_kernel *dev)
{
	spin_lock_irq(&irq_to_dev_lock);

	if (dev->guest_arch_irq) {
		WARN_ON(dev->guest_arch_irq->dev != dev);
		dev->guest_arch_irq->dev = NULL;
	}

	spin_unlock_irq(&irq_to_dev_lock);

	dev->irq_requested_type &= ~(KVM_DEV_IRQ_GUEST_MASK);
}

static void deassign_host_irq(struct kvm *kvm,
			      struct kvm_assigned_dev_kernel *assigned_dev)
{
	disable_irq(assigned_dev->host_irq);
	free_irq(assigned_dev->host_irq, (void *)assigned_dev);
	assigned_dev->irq_requested_type &= ~(KVM_DEV_IRQ_HOST_MASK);
}

static int kvm_deassign_irq(struct kvm *kvm,
			    struct kvm_assigned_dev_kernel *assigned_dev,
			    unsigned long irq_requested_type)
{
	unsigned long guest_irq_type, host_irq_type;

	if (!irqchip_in_kernel(kvm))
		return -EINVAL;
	/* no irq assignment to deassign */
	if (!assigned_dev->irq_requested_type)
		return -ENXIO;

	host_irq_type = irq_requested_type & KVM_DEV_IRQ_HOST_MASK;
	guest_irq_type = irq_requested_type & KVM_DEV_IRQ_GUEST_MASK;

	if (host_irq_type)
		deassign_host_irq(kvm, assigned_dev);
	if (guest_irq_type)
		deassign_guest_irq(kvm, assigned_dev);

	return 0;
}

static void kvm_free_assigned_irq(struct kvm *kvm,
				  struct kvm_assigned_dev_kernel *assigned_dev)
{
	kvm_deassign_irq(kvm, assigned_dev, assigned_dev->irq_requested_type);
}

static void kvm_free_assigned_device(struct kvm *kvm,
				     struct kvm_assigned_dev_kernel
				     *assigned_dev)
{
	kvm_free_assigned_irq(kvm, assigned_dev);
	list_del(&assigned_dev->list);
	kfree(assigned_dev);
}

void kvm_free_all_assigned_devices(struct kvm *kvm)
{
	struct list_head *ptr, *ptr2;
	struct kvm_assigned_dev_kernel *assigned_dev;

	list_for_each_safe(ptr, ptr2, &kvm->arch.assigned_dev_head) {
		assigned_dev = list_entry(ptr,
					  struct kvm_assigned_dev_kernel,
					  list);

		kvm_free_assigned_device(kvm, assigned_dev);
	}
}

static int get_linux_irq(struct kvm_assigned_irq *irq)
{
#ifdef __powerpc__
	/* TODO move into an arch callback */
	if (irq->assigned_dev_id != 0)
		return 0;

	if (irq->flags & KVM_SYSIRQ_DEVTREE_INTSPEC)
		return irq_create_of_mapping(NULL, irq->sysirq.intspec,
					     irq->sysirq.intspec_len);

	return irq_create_mapping(NULL, irq->host_irq);
#else
#warning Need to define interrupt numbers for this platform
	return irq->host_irq;
#endif
}

static int enable_host_system(struct kvm *kvm,
			      struct kvm_assigned_dev_kernel *dev,
			      struct kvm_assigned_irq *irq)
{
	int ret;

	dev->host_irq = get_linux_irq(irq);
	if (!dev->host_irq)
		return -ENXIO;

	switch (irq->flags & KVM_SYSIRQ_LEVEL_SENSE_MASK) {
	case KVM_SYSIRQ_DEFAULT:
		break;
	case KVM_SYSIRQ_LEVEL | KVM_SYSIRQ_LOW:
		irq_set_irq_type(dev->host_irq, IRQ_TYPE_LEVEL_LOW);
		break;
	case KVM_SYSIRQ_LEVEL | KVM_SYSIRQ_HIGH:
		irq_set_irq_type(dev->host_irq, IRQ_TYPE_LEVEL_HIGH);
		break;
	case KVM_SYSIRQ_EDGE | KVM_SYSIRQ_LOW:
		irq_set_irq_type(dev->host_irq, IRQ_TYPE_EDGE_FALLING);
		break;
	case KVM_SYSIRQ_EDGE | KVM_SYSIRQ_HIGH:
		irq_set_irq_type(dev->host_irq, IRQ_TYPE_EDGE_RISING);
		break;
	case KVM_SYSIRQ_EDGE | KVM_SYSIRQ_HIGH | KVM_SYSIRQ_LOW:
		irq_set_irq_type(dev->host_irq, IRQ_TYPE_EDGE_BOTH);
		break;
	default:
		return -EINVAL;
	}

	/* We don't want to use shared interrupts. Sharing host devices with
	 * guest-assigned devices on the same interrupt line is not a happy
	 * situation: there are going to be long delays in accepting,
	 * acking, etc.
	 */
	ret = request_irq(dev->host_irq, kvm_assigned_dev_intr,
			  0, "kvm_assigned_interrupt", (void *)dev);
	if (ret < 0)
		return ret;

	return 0;
}

static int enable_guest_system(struct kvm *kvm,
			       struct kvm_assigned_dev_kernel *dev,
			       struct kvm_assigned_irq *irq)
{
	struct kvm_arch_irq *arch_irq;
	int ret = 0;

	spin_lock_irq(&irq_to_dev_lock);

	arch_irq = kvm_arch_lookup_irq(kvm, irq);
	if (!arch_irq) {
		ret = -EINVAL;
		goto out;
	}

	WARN_ON(arch_irq->dev);
	WARN_ON(dev->guest_arch_irq);
	arch_irq->dev = dev;
	dev->guest_arch_irq = arch_irq;

out:
	spin_unlock_irq(&irq_to_dev_lock);
	return 0;
}

static int assign_host_irq(struct kvm *kvm,
			   struct kvm_assigned_dev_kernel *dev,
			   struct kvm_assigned_irq *irq,
			   __u32 host_irq_type)
{
	int r;

	r = enable_host_system(kvm, dev, irq);
	if (!r)
		dev->irq_requested_type |= host_irq_type;

	return r;
}

static int assign_guest_irq(struct kvm *kvm,
			    struct kvm_assigned_dev_kernel *dev,
			    struct kvm_assigned_irq *irq,
			    unsigned long guest_irq_type)
{
	int r;

	r = enable_guest_system(kvm, dev, irq);
	if (!r)
		dev->irq_requested_type |= guest_irq_type;

	return r;
}

static int kvm_vm_ioctl_assign_irq(struct kvm *kvm,
				   struct kvm_assigned_irq *assigned_irq)
{
	int r = -EINVAL;
	unsigned long host_irq_type, guest_irq_type;
	struct kvm_assigned_dev_kernel *dev;

	if (!irqchip_in_kernel(kvm))
		return r;

	mutex_lock(&kvm->lock);
	r = -ENODEV;

	if (assigned_irq->assigned_dev_id != 0)
		goto out;

	host_irq_type = (assigned_irq->flags & KVM_DEV_IRQ_HOST_MASK);
	guest_irq_type = (assigned_irq->flags & KVM_DEV_IRQ_GUEST_MASK);

	r = -EINVAL;
	if (host_irq_type != KVM_DEV_IRQ_HOST_SYSTEM ||
	    guest_irq_type != KVM_DEV_IRQ_GUEST_SYSTEM)
		goto out;

	r = -EEXIST;
	dev = kvm_find_system_irq(&kvm->arch.assigned_dev_head,
				  get_linux_irq(assigned_irq));
	if (dev)
		goto out;

	r = -ENOMEM;
	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		goto out;

	spin_lock_init(&dev->intx_lock);
	dev->kvm = kvm;

	list_add(&dev->list, &kvm->arch.assigned_dev_head);

	/*
	 * Assign the guest IRQ first, so that it is ready to accept
	 * a set_irq() as soon as the host IRQ is registered.
	 */
	r = assign_guest_irq(kvm, dev, assigned_irq, guest_irq_type);
	if (r)
		goto out_free;

	r = assign_host_irq(kvm, dev, assigned_irq, host_irq_type);
	if (r)
		goto out_guest;

	mutex_unlock(&kvm->lock);
	return 0;

out_guest:
	deassign_guest_irq(kvm, dev);
out_free:
	list_del(&dev->list);
	kfree(dev);
out:
	mutex_unlock(&kvm->lock);
	return r;
}

static int kvm_vm_ioctl_deassign_dev_irq(struct kvm *kvm,
					 struct kvm_assigned_irq
					 *assigned_irq)
{
	int r = -ENODEV;
	struct kvm_assigned_dev_kernel *match;

	mutex_lock(&kvm->lock);

	match = kvm_find_system_irq(&kvm->arch.assigned_dev_head,
				    get_linux_irq(assigned_irq));
	if (match)
		goto out;

	r = 0;
	kvm_free_assigned_device(kvm, match);
out:
	mutex_unlock(&kvm->lock);
	return r;
}

long kvm_vm_ioctl_assigned_device(struct kvm *kvm, unsigned ioctl,
				  unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	int r = -ENOTTY;

	switch (ioctl) {
	case KVM_ASSIGN_DEV_IRQ: {
		struct kvm_assigned_irq assigned_irq;

		r = -EFAULT;
		if (copy_from_user(&assigned_irq, argp, sizeof assigned_irq))
			goto out;
		r = kvm_vm_ioctl_assign_irq(kvm, &assigned_irq);
		if (r)
			goto out;
		break;
	}
	case KVM_DEASSIGN_DEV_IRQ: {
		struct kvm_assigned_irq assigned_irq;

		r = -EFAULT;
		if (copy_from_user(&assigned_irq, argp, sizeof assigned_irq))
			goto out;
		r = kvm_vm_ioctl_deassign_dev_irq(kvm, &assigned_irq);
		if (r)
			goto out;
		break;
	}
	}
out:
	return r;
}
