/*
 * Freescale eSDHC controller driver.
 *
 * Copyright (c) 2007, 2010 Freescale Semiconductor, Inc.
 * Copyright (c) 2009 MontaVista Software, Inc.
 *
 * Authors: Xiaobo Xie <X.Xie@freescale.com>
 *	    Anton Vorontsov <avorontsov@ru.mvista.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 */

#include <linux/io.h>
#include <linux/delay.h>
#include <linux/mmc/host.h>
#include "sdhci-of.h"
#include "sdhci.h"
#include "sdhci-esdhc.h"

static u16 esdhc_readw(struct sdhci_host *host, int reg)
{
	u16 ret;
	int base = reg & ~0x3;
	int shift = (reg & 0x2) * 8;

	if (unlikely(reg == SDHCI_HOST_VERSION))
		ret = in_be32(host->ioaddr + base) & 0xffff;
	else
		ret = (in_be32(host->ioaddr + base) >> shift) & 0xffff;
	return ret;
}

static u8 esdhc_readb(struct sdhci_host *host, int reg)
{
	int base = reg & ~0x3;
	int shift = (reg & 0x3) * 8;
	u8 ret = (in_be32(host->ioaddr + base) >> shift) & 0xff;
	return ret;
}

static void esdhc_writew(struct sdhci_host *host, u16 val, int reg)
{
	if (reg == SDHCI_BLOCK_SIZE) {
		/*
		 * Two last DMA bits are reserved, and first one is used for
		 * non-standard blksz of 4096 bytes that we don't support
		 * yet. So clear the DMA boundary bits.
		 */
		val &= ~SDHCI_MAKE_BLKSZ(0x7, 0);
	}
	sdhci_be32bs_writew(host, val, reg);
}

static void esdhc_writeb(struct sdhci_host *host, u8 val, int reg)
{
	/* Prevent SDHCI core from writing reserved bits (e.g. HISPD). */
	if (reg == SDHCI_HOST_CONTROL)
		val &= ~ESDHC_HOST_CONTROL_RES;
	sdhci_be32bs_writeb(host, val, reg);
}

static int esdhc_of_enable_dma(struct sdhci_host *host)
{
	setbits32(host->ioaddr + ESDHC_DMA_SYSCTL, ESDHC_DMA_SNOOP);
	return 0;
}

static unsigned int esdhc_of_get_max_clock(struct sdhci_host *host)
{
	struct sdhci_of_host *of_host = sdhci_priv(host);

	return of_host->clock;
}

static unsigned int esdhc_of_get_min_clock(struct sdhci_host *host)
{
	struct sdhci_of_host *of_host = sdhci_priv(host);

	return of_host->clock / 256 / 16;
}

#ifdef CONFIG_PM
static u32 esdhc_proctl;
static void esdhc_of_suspend(struct sdhci_host *host)
{
	esdhc_proctl = sdhci_be32bs_readl(host, SDHCI_HOST_CONTROL);
}

static void esdhc_of_resume(struct sdhci_host *host)
{
	esdhc_of_enable_dma(host);
	sdhci_be32bs_writel(host, esdhc_proctl, SDHCI_HOST_CONTROL);

}
#endif

struct sdhci_of_data sdhci_esdhc = {
	/* card detection could be handled via GPIO */
	.quirks = ESDHC_DEFAULT_QUIRKS | SDHCI_QUIRK_BROKEN_CARD_DETECTION
		| SDHCI_QUIRK_NO_CARD_NO_RESET,
	.ops = {
		.read_l = sdhci_be32bs_readl,
		.read_w = esdhc_readw,
		.read_b = esdhc_readb,
		.write_l = sdhci_be32bs_writel,
		.write_w = esdhc_writew,
		.write_b = esdhc_writeb,
		.set_clock = esdhc_set_clock,
		.enable_dma = esdhc_of_enable_dma,
		.get_max_clock = esdhc_of_get_max_clock,
		.get_min_clock = esdhc_of_get_min_clock,
#ifdef CONFIG_PM
		.platform_suspend = esdhc_of_suspend,
		.platform_resume = esdhc_of_resume,
#endif
	},
};
