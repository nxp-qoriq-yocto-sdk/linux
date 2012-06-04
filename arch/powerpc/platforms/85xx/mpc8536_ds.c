/*
 * MPC8536 DS Board Setup
 *
 * Copyright 2008 Freescale Semiconductor, Inc.
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */

#include <linux/stddef.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/kdev_t.h>
#include <linux/delay.h>
#include <linux/seq_file.h>
#include <linux/interrupt.h>
#include <linux/of_platform.h>
#include <linux/memblock.h>

#include <asm/system.h>
#include <asm/time.h>
#include <asm/machdep.h>
#include <asm/pci-bridge.h>
#include <mm/mmu_decl.h>
#include <asm/prom.h>
#include <asm/udbg.h>
#include <asm/mpic.h>
#include <asm/swiotlb.h>

#include <sysdev/fsl_soc.h>
#include <sysdev/fsl_pci.h>

void __init mpc8536_ds_pic_init(void)
{
	struct mpic *mpic;
	struct device_node *np;

	np = of_find_node_by_type(NULL, "open-pic");
	if (np == NULL) {
		printk(KERN_ERR "Could not find open-pic node\n");
		return;
	}

	mpic = mpic_alloc(np, 0,
			  MPIC_PRIMARY | MPIC_WANTS_RESET |
			  MPIC_BIG_ENDIAN | MPIC_BROKEN_FRR_NIRQS,
			0, 256, " OpenPIC  ");
	BUG_ON(mpic == NULL);
	of_node_put(np);

	mpic_init(mpic);
}

/*
 * Setup the architecture
 */
static void __init mpc8536_ds_setup_arch(void)
{
#ifdef CONFIG_PCI
	struct device_node *np;
#endif

	if (ppc_md.progress)
		ppc_md.progress("mpc8536_ds_setup_arch()", 0);

#ifdef CONFIG_PCI
	for_each_node_by_type(np, "pci")
		fsl_pci_setup(np);
#endif

#ifdef CONFIG_SWIOTLB
	if (memblock_end_of_DRAM() > 0xffffffff)
		ppc_swiotlb_enable = 1;
#endif

	printk("MPC8536 DS board from Freescale Semiconductor\n");
}

static struct of_device_id __initdata mpc8536ds_pci_ids[] = {
	{ .compatible = "fsl,mpc8540-pcie", },
	{ .compatible = "fsl,mpc8548-pcie", },
	{},
};

static int __init mpc8536_ds_publish_pci_device(void)
{
	return of_platform_bus_probe(NULL, mpc8536ds_pci_ids, NULL);
}
machine_arch_initcall(mpc8536_ds, mpc8536_ds_publish_pci_device);

static struct of_device_id __initdata mpc8536_ds_ids[] = {
	{ .type = "soc", },
	{ .compatible = "soc", },
	{ .compatible = "simple-bus", },
	{ .compatible = "gianfar", },
	{},
};

static int __init mpc8536_ds_publish_devices(void)
{
	return of_platform_bus_probe(NULL, mpc8536_ds_ids, NULL);
}
machine_device_initcall(mpc8536_ds, mpc8536_ds_publish_devices);

machine_arch_initcall(mpc8536_ds, swiotlb_setup_bus_notifier);

/*
 * Called very early, device-tree isn't unflattened
 */
static int __init mpc8536_ds_probe(void)
{
	unsigned long root = of_get_flat_dt_root();

	if (of_flat_dt_is_compatible(root, "fsl,mpc8536ds")) {
#ifdef CONFIG_PCI
		primary_phb_addr = 0x8000;
#endif
		return 1;
	}

	return 0;
}

define_machine(mpc8536_ds) {
	.name			= "MPC8536 DS",
	.probe			= mpc8536_ds_probe,
	.setup_arch		= mpc8536_ds_setup_arch,
	.init_IRQ		= mpc8536_ds_pic_init,
#ifdef CONFIG_PCI
	.pcibios_fixup_bus	= fsl_pcibios_fixup_bus,
#endif
	.get_irq		= mpic_get_irq,
	.restart		= fsl_rstcr_restart,
	.calibrate_decr		= generic_calibrate_decr,
	.progress		= udbg_progress,
};
