/*
 * Copyright (c) 2020 Lemonbeat GmbH
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define DT_DRV_COMPAT silabs_gecko_trng

 #include <drivers/entropy.h>
 #include <string.h>
 #include "soc.h"
 #include "em_cmu.h"
#ifdef CONFIG_SOC_GECKO_SEMAILBOX 
#include "sl_se_manager.h"
#include "sl_se_manager_attestation.h"
#include "sl_se_manager_util.h"
#include "sl_se_manager_entropy.h"
#include "sl_se_manager_key_handling.h"
#endif

#ifndef CONFIG_SOC_GECKO_SEMAILBOX
static void entropy_gecko_trng_read(uint8_t *output, size_t len)
{
	uint32_t tmp;
	uint32_t *data = (uint32_t *) output;
#ifndef CONFIG_CRYPTO_ACC_GECKO_TRNG
	/* Read known good available data. */
	while (len >= 4) {
		*data++ = TRNG0->FIFO;
		len -= 4;
	}
	if (len > 0) {
		/* Handle the case where len is not a multiple of 4
		 * and FIFO data is available.
		 */
		tmp = TRNG0->FIFO;
		memcpy(data, (const uint8_t *) &tmp, len);
	}
#else
	memcpy(output, ((const uint8_t *) CRYPTOACC_RNGOUT_FIFO_S_MEM_BASE), len);
#endif
}
#endif

static int entropy_gecko_trng_get_entropy(const struct device *dev,
					  uint8_t *buffer,
					  uint16_t length)
{
#ifndef CONFIG_SOC_GECKO_SEMAILBOX
	size_t count = 0;
	size_t available;

	ARG_UNUSED(dev);

	while (length) {
#ifndef CONFIG_CRYPTO_ACC_GECKO_TRNG
		available = TRNG0->FIFOLEVEL * 4;
#else
		available = CRYPTOACC_RNGCTRL->FIFOLEVEL * 4;
#endif
		if (available == 0) {
			return -EINVAL;
		}

		count = SL_MIN(length, available);
		entropy_gecko_trng_read(buffer, count);
		buffer += count;
		length -= count;
	}
	return 0;
#else
  	// Initialize command context.
  	sl_se_command_context_t cmd_ctx = { 0 };
  	sl_status_t sl_status = sl_se_get_random(&cmd_ctx, buffer, length);
  	return sl_status;
#endif
}

static int entropy_gecko_trng_get_entropy_isr(const struct device *dev,
					      uint8_t *buf,
					      uint16_t len, uint32_t flags)
{
#ifndef CONFIG_SOC_GECKO_SEMAILBOX
	if ((flags & ENTROPY_BUSYWAIT) == 0U) {

		/* No busy wait; return whatever data is available. */
		size_t count;
#ifndef CONFIG_CRYPTO_ACC_GECKO_TRNG
		size_t available = TRNG0->FIFOLEVEL * 4;
#else
		size_t available = CRYPTOACC_RNGCTRL->FIFOLEVEL * 4;
#endif

		if (available == 0) {
			return -ENODATA;
		}
		count = SL_MIN(len, available);
		entropy_gecko_trng_read(buf, count);
		return count;

	} else {
		/* Allowed to busy-wait */
		int ret = entropy_gecko_trng_get_entropy(dev, buf, len);

		if (ret == 0) {
			/* Data retrieved successfully. */
			return len;
		}
		return ret;
	}
#else
	int ret = entropy_gecko_trng_get_entropy(dev, buf, len);
	if (ret == 0) {
		/* Data retrieved successfully. */
		return len;
	}
	return ret;
#endif
}

static int entropy_gecko_trng_init(const struct device *dev)
{
#ifndef CONFIG_SOC_GECKO_SEMAILBOX
	/* Enable the TRNG0 clock. */
#ifndef CONFIG_CRYPTO_ACC_GECKO_TRNG
	CMU_ClockEnable(cmuClock_TRNG0, true);

	/* Enable TRNG0. */
	TRNG0->CONTROL = TRNG_CONTROL_ENABLE;
#else
	/* Enable the CRYPTO ACC clock. */
	CMU_ClockEnable(cmuClock_CRYPTOACC, true);

	/* Enable TRNG */
	CRYPTOACC_RNGCTRL->RNGCTRL |= CRYPTOACC_RNGCTRL_ENABLE;
#endif
#endif
	return 0;
}

static struct entropy_driver_api entropy_gecko_trng_api_funcs = {
	.get_entropy = entropy_gecko_trng_get_entropy,
	.get_entropy_isr = entropy_gecko_trng_get_entropy_isr
};

DEVICE_DT_INST_DEFINE(0,
			entropy_gecko_trng_init, NULL,
			NULL, NULL,
			PRE_KERNEL_1, CONFIG_ENTROPY_INIT_PRIORITY,
			&entropy_gecko_trng_api_funcs);
