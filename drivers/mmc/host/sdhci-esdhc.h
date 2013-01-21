/*
 * Freescale eSDHC controller driver generics for OF and pltfm.
 *
 * Copyright (c) 2007, 2011 Freescale Semiconductor, Inc.
 * Copyright (c) 2009 MontaVista Software, Inc.
 * Copyright (c) 2010 Pengutronix e.K.
 *   Author: Wolfram Sang <w.sang@pengutronix.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License.
 */

#ifndef _DRIVERS_MMC_SDHCI_ESDHC_H
#define _DRIVERS_MMC_SDHCI_ESDHC_H

/*
 * Ops and quirks for the Freescale eSDHC controller.
 */

#define ESDHC_DEFAULT_QUIRKS	(SDHCI_QUIRK_FORCE_BLK_SZ_2048 | \
				SDHCI_QUIRK_NO_BUSY_IRQ | \
				SDHCI_QUIRK_NONSTANDARD_CLOCK | \
				SDHCI_QUIRK_DATA_TIMEOUT_USES_SDCLK | \
				SDHCI_QUIRK_PIO_NEEDS_DELAY | \
				SDHCI_QUIRK_RESTORE_IRQS_AFTER_RESET)

#define ESDHC_SYSTEM_CONTROL	0x2c
#define ESDHC_CLOCK_MASK	0x0000fff0
#define ESDHC_PREDIV_SHIFT	8
#define ESDHC_DIVIDER_SHIFT	4
#define ESDHC_CLOCK_ENABLE	0x00000008
#define ESDHC_CLOCK_PEREN	0x00000004
#define ESDHC_CLOCK_HCKEN	0x00000002
#define ESDHC_CLOCK_IPGEN	0x00000001

#define ESDHCI_CLOCK_STABLE	0x00000008
/* pltfm-specific */
#define ESDHC_HOST_CONTROL_LE	0x20

/* OF-specific */
#define ESDHC_DMA_SYSCTL	0x40c
#define ESDHC_DMA_SNOOP		0x00000040

#define ESDHC_HOST_CONTROL_RES	0x05

static inline int esdhc_version_check(struct sdhci_host *host)
{
	unsigned int svr;

	svr = mfspr(SPRN_SVR);

	/*
	 * Only T4240 and B4860 with Revision 1.0 had this issue and
	 * it will be fixed in Revision 2.0.
	 * T4240 SVR: 0x24, Revision: 0x10 (v1.0).
	 * B4860 SVR: 0x68, Revision: 0x10 (v1.0).
	 */

	if (((((svr >> 20) & 0xFF) == 0x24) && ((svr & 0xFF) == 0x10)) ||
		((((svr >> 20) & 0xFF) == 0x68) && ((svr & 0xFF) == 0x10)))
		return 1;
	else
		return 0;
}

static inline void esdhc_set_clock(struct sdhci_host *host, unsigned int clock)
{
	int pre_div = 2;
	int div = 1;
	u32 temp;
	u32 mask = 0;
	u32 timeout;

	if (clock == 0)
		goto out;

	mask = (ESDHC_CLOCK_IPGEN | ESDHC_CLOCK_HCKEN | ESDHC_CLOCK_PEREN
		| ESDHC_CLOCK_MASK);

	if (esdhc_version_check(host))
		mask |= ESDHC_CLOCK_ENABLE;

	temp = sdhci_readl(host, ESDHC_SYSTEM_CONTROL);
	temp &= ~mask;
	sdhci_writel(host, temp, ESDHC_SYSTEM_CONTROL);

	while (host->max_clk / pre_div / 16 > clock && pre_div < 256)
		pre_div *= 2;

	while (host->max_clk / pre_div / div > clock && div < 16)
		div++;

	dev_dbg(mmc_dev(host->mmc), "desired SD clock: %d, actual: %d\n",
		clock, host->max_clk / pre_div / div);

	pre_div >>= 1;
	div--;

	temp = sdhci_readl(host, ESDHC_SYSTEM_CONTROL);
	temp |= (ESDHC_CLOCK_IPGEN | ESDHC_CLOCK_HCKEN | ESDHC_CLOCK_PEREN
		| (div << ESDHC_DIVIDER_SHIFT)
		| (pre_div << ESDHC_PREDIV_SHIFT));
	sdhci_writel(host, temp, ESDHC_SYSTEM_CONTROL);

	if (esdhc_version_check(host)) {

		/* we are here because of these boards need to check
		 * if the clock was stable, when clock was changed
		 * or reset for all bit was changed.
		 */

		/* Wait max 20 ms */
		timeout = 20;
		mask = ESDHCI_CLOCK_STABLE;
		while (!(sdhci_readl(host, SDHCI_PRESENT_STATE) & mask)) {
			if (timeout == 0) {
				pr_err("%s: Internal clock never "
					"stabilised.\n",
					mmc_hostname(host->mmc));
				return;
			}
			timeout--;
			mdelay(1);
		}

		temp |= ESDHC_CLOCK_ENABLE;
		sdhci_writel(host, temp, ESDHC_SYSTEM_CONTROL);
	}

out:
	host->clock = clock;
}

#endif /* _DRIVERS_MMC_SDHCI_ESDHC_H */
