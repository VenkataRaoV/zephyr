# SPDX-License-Identifier: Apache-2.0

zephyr_sources(soc.c soc_gpio.c)

zephyr_sources_ifdef((CONFIG_SERIES_2 && CONFIG_PM) soc_power.c)
zephyr_include_directories(.)
