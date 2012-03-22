/*
 * BSC913xRDB Board Setup
 *
 * Author: Priyanka Jain <Priyanka.Jain@freescale.com>
 *
 * Copyright 2011-2012 Freescale Semiconductor Inc.
 *
 * This program is free software; you can redistribute	it and/or modify it
 * under  the terms of	the GNU General	 Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */

#include <linux/of_platform.h>
#include <linux/pci.h>
#include <asm/mpic.h>
#include <sysdev/fsl_soc.h>
#include <asm/udbg.h>

void __init bsc913x_rdb_pic_init(void)
{
	struct mpic *mpic;
	struct resource r;
	struct device_node *np;

	np = of_find_node_by_type(NULL, "open-pic");
	if (!np) {
		pr_err("bsc913x: Could not find open-pic node\n");
		return;
	}

	if (of_address_to_resource(np, 0, &r)) {
		pr_err("bsc913x: Failed to map mpic register space\n");
		of_node_put(np);
		return;
	}

	mpic = mpic_alloc(np, r.start, MPIC_PRIMARY | MPIC_WANTS_RESET |
			  MPIC_BIG_ENDIAN | MPIC_BROKEN_FRR_NIRQS | MPIC_SINGLE_DEST_CPU,
			  0, 256, " OpenPIC  ");

	of_node_put(np);

	if (!mpic)
		pr_err("bsc913x: Failed to allocate MPIC structure\n");
	else
		mpic_init(mpic);
}

/*
 * Setup the architecture
 */
static void __init bsc913x_rdb_setup_arch(void)
{
	if (ppc_md.progress)
		ppc_md.progress("bsc913x_rdb_setup_arch()", 0);

	pr_info("bsc913x board from Freescale Semiconductor\n");
}

static struct of_device_id __initdata bsc913x_rdb_ids[] = {
	{ .type = "soc", },
	{ .compatible = "soc", },
	{ .compatible = "simple-bus", },
	{ .compatible = "gianfar", },
	{},
};

static int __init bsc913x_rdb_publish_devices(void)
{
	return of_platform_bus_probe(NULL, bsc913x_rdb_ids, NULL);
}

machine_device_initcall(bsc9131_rdb, bsc913x_rdb_publish_devices);

/*
 * Called very early, device-tree isn't unflattened
 */

static int __init bsc9131_rdb_probe(void)
{
	unsigned long root = of_get_flat_dt_root();

	return of_flat_dt_is_compatible(root, "fsl,bsc9131rdb");
}

define_machine(bsc9131_rdb) {
	.name			= "BSC9131 RDB",
	.probe			= bsc9131_rdb_probe,
	.setup_arch		= bsc913x_rdb_setup_arch,
	.init_IRQ		= bsc913x_rdb_pic_init,
	.get_irq		= mpic_get_irq,
	.restart		= fsl_rstcr_restart,
	.calibrate_decr		= generic_calibrate_decr,
	.progress		= udbg_progress,
};
