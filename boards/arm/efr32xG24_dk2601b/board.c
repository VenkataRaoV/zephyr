/*
 * Copyright (c) 2021 Sateesh Kotapati
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <init.h>
#include <drivers/gpio.h>
#include <sys/printk.h>
#include <logging/log.h>

LOG_MODULE_REGISTER(efr32xG24_dk2601b, LOG_LEVEL_DBG);

/* This pin is used to enable the serial port using the board controller */
#define VCOM_ENABLE_GPIO_NAME  "GPIO_A"
#define VCOM_ENABLE_GPIO_PIN   5

static int efr32xG24_dk2601b_init(const struct device *dev)
{
	const struct device *vce_dev; /* Virtual COM Port Enable GPIO Device */

	ARG_UNUSED(dev);

	/* Enable the board controller to be able to use the serial port */
	vce_dev = device_get_binding(VCOM_ENABLE_GPIO_NAME);
	if (!vce_dev) {
		LOG_ERR("Virtual COM Port Enable device was not found!\n");
		return -ENODEV;
	}

	gpio_pin_configure(vce_dev, VCOM_ENABLE_GPIO_PIN, GPIO_OUTPUT_HIGH);

	return 0;
}

/* needs to be done after GPIO driver init */
SYS_INIT(efr32xG24_dk2601b_init, POST_KERNEL, CONFIG_KERNEL_INIT_PRIORITY_DEVICE);
