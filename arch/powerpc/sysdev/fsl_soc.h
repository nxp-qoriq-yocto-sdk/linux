#ifndef __PPC_FSL_SOC_H
#define __PPC_FSL_SOC_H
#ifdef __KERNEL__

#include <asm/mmu.h>
#include <linux/platform_device.h>

struct spi_device;

extern phys_addr_t get_immrbase(void);
#if defined(CONFIG_CPM2) || defined(CONFIG_QUICC_ENGINE) || defined(CONFIG_8xx)
extern u32 get_brgfreq(void);
extern u32 get_baudrate(void);
#else
static inline u32 get_brgfreq(void) { return -1; }
static inline u32 get_baudrate(void) { return -1; }
#endif
extern u32 fsl_get_sys_freq(void);

struct spi_board_info;
struct device_node;

extern void fsl_rstcr_restart(char *cmd);

#ifdef CONFIG_FSL_PMC
int mpc85xx_pmc_set_wake(struct platform_device *pdev, bool enable);
void mpc85xx_pmc_set_lossless_ethernet(int enable);
#else
#define mpc85xx_pmc_set_wake(pdev, enable)
#define mpc85xx_pmc_set_lossless_ethernet(enable)
#endif

#if defined(CONFIG_FB_FSL_DIU) || defined(CONFIG_FB_FSL_DIU_MODULE)
struct platform_diu_data_ops {
	unsigned int (*get_pixel_format) (unsigned int bits_per_pixel,
		int monitor_port);
	void (*set_gamma_table) (int monitor_port, char *gamma_table_base);
	void (*set_monitor_port) (int monitor_port);
	void (*set_pixel_clock) (unsigned int pixclock);
	ssize_t (*show_monitor_port) (int monitor_port, char *buf);
	int (*set_sysfs_monitor_port) (int val);
	void (*release_bootmem) (void);
};

extern struct platform_diu_data_ops diu_ops;
#endif

void fsl_hv_restart(char *cmd);
void fsl_hv_halt(void);

/*
 * Cast the ccsrbar to 64-bit parameter so that the assembly
 * code can be compatible with both 32-bit & 36-bit.
 */
extern void mpc85xx_enter_deep_sleep(u64 ccsrbar, u32 powmgtreq);

static inline void mpc85xx_enter_jog(u64 ccsrbar, u32 powmgtreq)
{
	mpc85xx_enter_deep_sleep(ccsrbar, powmgtreq);
}
#endif
#endif
