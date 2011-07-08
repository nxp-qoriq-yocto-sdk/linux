/*
 * Copyright (C) 2007-2010 Freescale Semiconductor, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 */

#ifndef DOORBELL_H
#define DOORBELL_H

#define MSG_DBELL         0x00000000
#define MSG_DBELL_CRIT    0x08000000
#define MSG_DBELL_BRDCAST 0x04000000
#define MSG_GBELL         0x10000000
#define MSG_GBELL_CRIT    0x18000000
#define MSG_GBELL_MCHK    0x20000000

static inline void send_doorbell_msg(unsigned long msg)
{
	/* msgsnd is ordered as a store relative to sync instructions,
	 * but not as a cacheable store, so we need a full sync
	 * to order with any previous stores that the doorbell handler
	 * needs to see.
	 */
	asm volatile("msync; msgsnd %0" : : "r" (msg) : "memory");
}

/** Send critical doorbell.
 *
 *  Always for hypervisor internal use only so
 *  the lpid is always 0.
 */
static inline void send_crit_doorbell(int cpunum)
{
	send_doorbell_msg(MSG_DBELL_CRIT | cpunum);
}

/** Send critical doorbell broadcast.
 *
 *  Always for hypervisor internal use
 */
static inline void send_crit_doorbell_brdcast(void)
{
	send_doorbell_msg(MSG_DBELL_CRIT | MSG_DBELL_BRDCAST);
}

/** Send doorbell.
 *
 *  Always for hypervisor internal use only so
 *  the lpid is always 0.
 */
static inline void send_doorbell(int cpunum)
{
	send_doorbell_msg(MSG_DBELL | cpunum);
}
#endif
