/*
 * Copyright (c) 2018 - 2020 Nordic Semiconductor ASA
 * Copyright (c) 2018 Ioannis Glaropoulos
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#if defined(CONFIG_SOC_NRF5340_CPUNET) || defined(DPPI_PRESENT)

#include <hal/nrf_dppi.h>
#include <hal/nrf_timer.h>
#include <hal/nrf_radio.h>
#include <hal/nrf_rtc.h>
#include <hal/nrf_ccm.h>
#include <hal/nrf_aar.h>
#include <hal/nrf_gpiote.h>

#include "radio_nrf5_dppi_resources.h"

static inline void hal_radio_nrf_ppi_channels_enable(uint32_t mask)
{
	nrf_dppi_channels_enable(NRF_DPPIC, mask);
}

static inline void hal_radio_nrf_ppi_channels_disable(uint32_t mask)
{
	nrf_dppi_channels_disable(NRF_DPPIC, mask);
}

/*******************************************************************************
 * Enable Radio on Event Timer tick:
 * wire the EVENT_TIMER EVENTS_COMPARE[0] event to RADIO TASKS_TXEN/RXEN task.
 */
static inline void hal_radio_enable_on_tick_ppi_config_and_enable(uint8_t trx)
{
	nrf_timer_publish_set(EVENT_TIMER, NRF_TIMER_EVENT_COMPARE0, HAL_RADIO_ENABLE_ON_TICK_PPI);

	if (trx) {
		nrf_radio_subscribe_set(NRF_RADIO,
					NRF_RADIO_TASK_TXEN, HAL_RADIO_ENABLE_TX_ON_TICK_PPI);

		/* Address nRF5340 Engineering A Errata 16 */
		if (IS_ENABLED(CONFIG_BT_CTLR_TIFS_HW)) {
			nrf_radio_subscribe_clear(NRF_RADIO, NRF_RADIO_TASK_RXEN);
		}
	} else {
		nrf_radio_subscribe_set(NRF_RADIO,
					NRF_RADIO_TASK_RXEN, HAL_RADIO_ENABLE_RX_ON_TICK_PPI);

		/* Address nRF5340 Engineering A Errata 16 */
		if (IS_ENABLED(CONFIG_BT_CTLR_TIFS_HW)) {
			nrf_radio_subscribe_clear(NRF_RADIO, NRF_RADIO_TASK_TXEN);
		}
	}

	nrf_dppi_channels_enable(NRF_DPPIC, BIT(HAL_RADIO_ENABLE_ON_TICK_PPI));
}

/*******************************************************************************
 * Capture event timer on Address reception:
 * wire the RADIO EVENTS_ADDRESS event to the
 * EVENT_TIMER TASKS_CAPTURE[<address timer>] task.
 */
static inline void hal_radio_recv_timeout_cancel_ppi_config(void)
{
	nrf_radio_publish_set(NRF_RADIO,
			      NRF_RADIO_EVENT_ADDRESS, HAL_RADIO_RECV_TIMEOUT_CANCEL_PPI);
	nrf_timer_subscribe_set(EVENT_TIMER,
				NRF_TIMER_TASK_CAPTURE1, HAL_RADIO_RECV_TIMEOUT_CANCEL_PPI);
}

/*******************************************************************************
 * Disable Radio on HCTO:
 * wire the EVENT_TIMER EVENTS_COMPARE[<HCTO timer>] event
 * to the RADIO TASKS_DISABLE task.
 */
static inline void hal_radio_disable_on_hcto_ppi_config(void)
{
	nrf_timer_publish_set(EVENT_TIMER,
			      NRF_TIMER_EVENT_COMPARE1, HAL_RADIO_DISABLE_ON_HCTO_PPI);
	nrf_radio_subscribe_set(NRF_RADIO,
				NRF_RADIO_TASK_DISABLE, HAL_RADIO_DISABLE_ON_HCTO_PPI);
}

/*******************************************************************************
 * Capture event timer on Radio end:
 * wire the RADIO EVENTS_END event to the
 * EVENT_TIMER TASKS_CAPTURE[<radio end timer>] task.
 */
static inline void hal_radio_end_time_capture_ppi_config(void)
{
	nrf_radio_publish_set(NRF_RADIO, NRF_RADIO_EVENT_END, HAL_RADIO_END_TIME_CAPTURE_PPI);
	nrf_timer_subscribe_set(EVENT_TIMER,
				NRF_TIMER_TASK_CAPTURE2, HAL_RADIO_END_TIME_CAPTURE_PPI);
}

/*******************************************************************************
 * Start event timer on RTC tick:
 * wire the RTC0 EVENTS_COMPARE[2] event to EVENT_TIMER  TASKS_START task.
 */
static inline void hal_event_timer_start_ppi_config(void)
{
	nrf_rtc_publish_set(NRF_RTC0, NRF_RTC_EVENT_COMPARE_2, HAL_EVENT_TIMER_START_PPI);
	nrf_timer_subscribe_set(EVENT_TIMER, NRF_TIMER_TASK_START, HAL_EVENT_TIMER_START_PPI);
}

/*******************************************************************************
 * Capture event timer on Radio ready:
 * wire the RADIO EVENTS_READY event to the
 * EVENT_TIMER TASKS_CAPTURE[<radio ready timer>] task.
 */
static inline void hal_radio_ready_time_capture_ppi_config(void)
{
	nrf_radio_publish_set(NRF_RADIO,
			      NRF_RADIO_EVENT_READY, HAL_RADIO_READY_TIME_CAPTURE_PPI);
	nrf_timer_subscribe_set(EVENT_TIMER,
				NRF_TIMER_TASK_CAPTURE0, HAL_RADIO_READY_TIME_CAPTURE_PPI);
}

/*******************************************************************************
 * Trigger encryption task upon address reception:
 * wire the RADIO EVENTS_ADDRESS event to the CCM TASKS_CRYPT task.
 *
 * Note: we do not need an additional PPI, since we have already set up
 * a PPI to publish RADIO ADDRESS event.
 */
static inline void hal_trigger_crypt_ppi_config(void)
{
	nrf_radio_publish_set(NRF_RADIO,
			      NRF_RADIO_EVENT_ADDRESS, HAL_RADIO_RECV_TIMEOUT_CANCEL_PPI);
	nrf_ccm_subscribe_set(NRF_CCM, NRF_CCM_TASK_CRYPT, HAL_RADIO_RECV_TIMEOUT_CANCEL_PPI);
}

/*******************************************************************************
 * Trigger automatic address resolution on Bit counter match:
 * wire the RADIO EVENTS_BCMATCH event to the AAR TASKS_START task.
 */
static inline void hal_trigger_aar_ppi_config(void)
{
	nrf_radio_publish_set(NRF_RADIO, NRF_RADIO_EVENT_BCMATCH, HAL_TRIGGER_AAR_PPI);
	nrf_aar_subscribe_set(NRF_AAR, NRF_AAR_TASK_START, HAL_TRIGGER_AAR_PPI);
}

/*******************************************************************************
 * Trigger Radio Rate override upon Rateboost event.
 */
static inline void hal_trigger_rateoverride_ppi_config(void)
{
	nrf_radio_publish_set(NRF_RADIO, NRF_RADIO_EVENT_RATEBOOST, HAL_TRIGGER_RATEOVERRIDE_PPI);
	nrf_ccm_subscribe_set(NRF_CCM, NRF_CCM_TASK_RATEOVERRIDE, HAL_TRIGGER_RATEOVERRIDE_PPI);
}

/******************************************************************************/
#if defined(HAL_RADIO_GPIO_HAVE_PA_PIN) || defined(HAL_RADIO_GPIO_HAVE_LNA_PIN)
static inline void hal_palna_ppi_setup(void)
{
	nrf_timer_publish_set(EVENT_TIMER, NRF_TIMER_EVENT_COMPARE2,
			      HAL_ENABLE_PALNA_PPI);
	nrf_radio_publish_set(NRF_RADIO, NRF_RADIO_EVENT_DISABLED,
			      HAL_DISABLE_PALNA_PPI);

#if !defined(HAL_RADIO_FEM_IS_NRF21540)
	nrf_gpiote_task_t task;

	task = nrf_gpiote_out_task_get(HAL_PALNA_GPIOTE_CHAN);
	nrf_gpiote_subscribe_set(NRF_GPIOTE, task, HAL_DISABLE_PALNA_PPI);
#endif
}
#endif /* defined(HAL_RADIO_GPIO_HAVE_PA_PIN) || defined(HAL_RADIO_GPIO_HAVE_LNA_PIN) */

/******************************************************************************/
#if defined(HAL_RADIO_FEM_IS_NRF21540)

static inline void hal_pa_ppi_setup(void)
{
	nrf_gpiote_task_t task;

#if defined(HAL_RADIO_GPIO_PA_POL_INV)
	task = nrf_gpiote_clr_task_get(HAL_PALNA_GPIOTE_CHAN);
	nrf_gpiote_subscribe_set(NRF_GPIOTE, task, HAL_ENABLE_PALNA_PPI);
	task = nrf_gpiote_set_task_get(HAL_PALNA_GPIOTE_CHAN);
	nrf_gpiote_subscribe_set(NRF_GPIOTE, task, HAL_DISABLE_PALNA_PPI);
#else /* !HAL_RADIO_GPIO_PA_POL_INV */
	task = nrf_gpiote_set_task_get(HAL_PALNA_GPIOTE_CHAN);
	nrf_gpiote_subscribe_set(NRF_GPIOTE, task, HAL_ENABLE_PALNA_PPI);
	task = nrf_gpiote_clr_task_get(HAL_PALNA_GPIOTE_CHAN);
	nrf_gpiote_subscribe_set(NRF_GPIOTE, task, HAL_DISABLE_PALNA_PPI);
#endif /* !HAL_RADIO_GPIO_PA_POL_INV */
}

static inline void hal_lna_ppi_setup(void)
{
	nrf_gpiote_task_t task;

#if defined(HAL_RADIO_GPIO_LNA_POL_INV)
	task = nrf_gpiote_clr_task_get(HAL_PALNA_GPIOTE_CHAN);
	nrf_gpiote_subscribe_set(NRF_GPIOTE, task, HAL_ENABLE_PALNA_PPI);
	task = nrf_gpiote_set_task_get(HAL_PALNA_GPIOTE_CHAN);
	nrf_gpiote_subscribe_set(NRF_GPIOTE, task, HAL_DISABLE_PALNA_PPI);
#else /* !HAL_RADIO_GPIO_LNA_POL_INV */
	task = nrf_gpiote_set_task_get(HAL_PALNA_GPIOTE_CHAN);
	nrf_gpiote_subscribe_set(NRF_GPIOTE, task, HAL_ENABLE_PALNA_PPI);
	task = nrf_gpiote_clr_task_get(HAL_PALNA_GPIOTE_CHAN);
	nrf_gpiote_subscribe_set(NRF_GPIOTE, task, HAL_DISABLE_PALNA_PPI);
#endif /* !HAL_RADIO_GPIO_LNA_POL_INV */
}

static inline void hal_fem_ppi_setup(void)
{
	nrf_gpiote_task_t task;

	nrf_timer_publish_set(EVENT_TIMER, NRF_TIMER_EVENT_COMPARE3,
			      HAL_ENABLE_FEM_PPI);
	nrf_radio_publish_set(NRF_RADIO, NRF_RADIO_EVENT_DISABLED,
			      HAL_DISABLE_FEM_PPI);

#if defined(HAL_RADIO_GPIO_NRF21540_PDN_POL_INV)
	task = nrf_gpiote_clr_task_get(HAL_PDN_GPIOTE_CHAN);
	nrf_gpiote_subscribe_set(NRF_GPIOTE, task, HAL_ENABLE_FEM_PPI);
	task = nrf_gpiote_set_task_get(HAL_PDN_GPIOTE_CHAN);
	nrf_gpiote_subscribe_set(NRF_GPIOTE, task, HAL_DISABLE_FEM_PPI);
#else /* !HAL_RADIO_GPIO_NRF21540_PDN_POL_INV */
	task = nrf_gpiote_set_task_get(HAL_PDN_GPIOTE_CHAN);
	nrf_gpiote_subscribe_set(NRF_GPIOTE, task, HAL_ENABLE_FEM_PPI);
	task = nrf_gpiote_clr_task_get(HAL_PDN_GPIOTE_CHAN);
	nrf_gpiote_subscribe_set(NRF_GPIOTE, task, HAL_DISABLE_FEM_PPI);
#endif /* !HAL_RADIO_GPIO_NRF21540_PDN_POL_INV */

#if defined(HAL_RADIO_GPIO_NRF21540_CSN_POL_INV)
	task = nrf_gpiote_clr_task_get(HAL_CSN_GPIOTE_CHAN);
	nrf_gpiote_subscribe_set(NRF_GPIOTE, task, HAL_ENABLE_FEM_PPI);
	task = nrf_gpiote_set_task_get(HAL_CSN_GPIOTE_CHAN);
	nrf_gpiote_subscribe_set(NRF_GPIOTE, task, HAL_DISABLE_FEM_PPI);
#else /* !HAL_RADIO_GPIO_NRF21540_CSN_POL_INV */
	task = nrf_gpiote_set_task_get(HAL_CSN_GPIOTE_CHAN);
	nrf_gpiote_subscribe_set(NRF_GPIOTE, task, HAL_ENABLE_FEM_PPI);
	task = nrf_gpiote_clr_task_get(HAL_CSN_GPIOTE_CHAN);
	nrf_gpiote_subscribe_set(NRF_GPIOTE, task, HAL_DISABLE_FEM_PPI);
#endif /* !HAL_RADIO_GPIO_NRF21540_CSN_POL_INV */
}

#endif /* HAL_RADIO_FEM_IS_NRF21540 */

/******************************************************************************/
#if !defined(CONFIG_BT_CTLR_TIFS_HW)

#if !defined(CONFIG_BT_CTLR_SW_SWITCH_SINGLE_TIMER)
#define NRF_RADIO_PUBLISH_PDU_END_EVT PUBLISH_PHYEND
/* Wrappenr for EVENTS_END event name used by nRFX API */
#define NRFX_RADIO_TXRX_END_EVENT NRF_RADIO_EVENT_PHYEND
#else
#define NRF_RADIO_PUBLISH_PDU_END_EVT PUBLISH_END
#define NRFX_RADIO_TXRX_END_EVENT NRF_RADIO_EVENT_END
#endif /* !CONFIG_BT_CTLR_SW_SWITCH_SINGLE_TIMER */

/* DPPI setup used for SW-based auto-switching during TIFS. */

/* Clear SW-switch timer on packet end:
 * wire the RADIO EVENTS_END event to SW_SWITCH_TIMER TASKS_CLEAR task.
 *
 * Note: In case of HW TIFS support or single timer configuration we do not need
 * an additional PPI, since we have already set up a PPI to publish RADIO END
 * event. In other case separate PPI is used because packet end is marked by
 * PHYEND event while last bit or CRC is marked by END event.
 */
static inline void hal_sw_switch_timer_clear_ppi_config(void)
{
	nrf_radio_publish_set(NRF_RADIO, NRFX_RADIO_TXRX_END_EVENT, HAL_SW_SWITCH_TIMER_CLEAR_PPI);
	nrf_timer_subscribe_set(SW_SWITCH_TIMER,
				NRF_TIMER_TASK_CLEAR, HAL_SW_SWITCH_TIMER_CLEAR_PPI);

	/* NOTE: nRF5340 may share the DPPI channel being triggered by Radio End,
	 *       for End time capture and sw_switch DPPI channel toggling.
	 *       The channel must be always enabled when software switch is used.
	 */
	nrf_dppi_channels_enable(NRF_DPPIC, BIT(HAL_SW_SWITCH_TIMER_CLEAR_PPI));
}

/* The 2 adjacent PPI groups used for implementing SW_SWITCH_TIMER-based
 * auto-switch for TIFS. 'index' must be 0 or 1.
 */
#define SW_SWITCH_TIMER_TASK_GROUP(index) \
	(SW_SWITCH_TIMER_TASK_GROUP_BASE + (index))

/* The 2 adjacent TIMER EVENTS_COMPARE event offsets used for implementing
 * SW_SWITCH_TIMER-based auto-switch for TIFS. 'index' must be 0 or 1.
 */
#define SW_SWITCH_TIMER_EVTS_COMP(index) \
	(SW_SWITCH_TIMER_EVTS_COMP_BASE + (index))

/* The 2 adjacent TIMER EVENTS_COMPARE event offsets used for implementing
 * SW_SWITCH_TIMER-based auto-switch for TIFS, when receiving on LE Coded
 * PHY. 'index' must be 0 or 1.
 */
#define SW_SWITCH_TIMER_S2_EVTS_COMP(index) \
	(SW_SWITCH_TIMER_EVTS_COMP_S2_BASE + (index))

/* Wire a SW SWITCH TIMER EVENTS_COMPARE[<cc_offset>] event
 * to a PPI GROUP TASK DISABLE task (PPI group with index <index>).
 * 2 adjacent PPIs (8 & 9) and 2 adjacent PPI groups are used for this wiring;
 * <index> must be 0 or 1. <offset> must be a valid TIMER CC register offset.
 */
#define HAL_SW_SWITCH_GROUP_TASK_DISABLE_PPI(index) \
	(HAL_SW_SWITCH_GROUP_TASK_DISABLE_PPI_BASE + (index))

#define HAL_SW_SWITCH_GROUP_TASK_DISABLE_PPI_REGISTER_EVT(cc_offset) \
	SW_SWITCH_TIMER->PUBLISH_COMPARE[cc_offset]
#define HAL_SW_SWITCH_GROUP_TASK_DISABLE_PPI_EVT(chan) \
	(((chan << TIMER_PUBLISH_COMPARE_CHIDX_Pos) \
		& TIMER_PUBLISH_COMPARE_CHIDX_Msk) | \
	((TIMER_PUBLISH_COMPARE_EN_Enabled << TIMER_PUBLISH_COMPARE_EN_Pos) \
		& TIMER_PUBLISH_COMPARE_EN_Msk))
#define HAL_SW_SWITCH_GROUP_TASK_DISABLE_PPI_REGISTER_TASK(index) \
	NRF_DPPIC->SUBSCRIBE_CHG[SW_SWITCH_TIMER_TASK_GROUP(index)].DIS
#define HAL_SW_SWITCH_GROUP_TASK_DISABLE_PPI_TASK(chan) \
	(((chan << DPPIC_SUBSCRIBE_CHG_DIS_CHIDX_Pos) \
		& DPPIC_SUBSCRIBE_CHG_DIS_CHIDX_Msk) | \
	((DPPIC_SUBSCRIBE_CHG_DIS_EN_Enabled << \
			DPPIC_SUBSCRIBE_CHG_DIS_EN_Pos) \
		& DPPIC_SUBSCRIBE_CHG_DIS_EN_Msk))

/* Enable the SW Switch PPI Group on RADIO END Event.
 *
 * Note: we do not need an additional PPI, since we have already set up
 * a PPI to publish RADIO END event.
 */
#define HAL_SW_SWITCH_GROUP_TASK_ENABLE_PPI_REGISTER_EVT (NRF_RADIO->NRF_RADIO_PUBLISH_PDU_END_EVT)
#define HAL_SW_SWITCH_GROUP_TASK_ENABLE_PPI_EVT \
	(((HAL_SW_SWITCH_GROUP_TASK_ENABLE_PPI << \
		RADIO_PUBLISH_END_CHIDX_Pos) \
		&	RADIO_PUBLISH_END_CHIDX_Msk) | \
	((RADIO_PUBLISH_END_EN_Enabled << RADIO_PUBLISH_END_EN_Pos) \
		& RADIO_PUBLISH_END_EN_Msk))
#define HAL_SW_SWITCH_GROUP_TASK_ENABLE_PPI_REGISTER_TASK(index) \
	(NRF_DPPIC->SUBSCRIBE_CHG[SW_SWITCH_TIMER_TASK_GROUP(index)].EN)
#define HAL_SW_SWITCH_GROUP_TASK_ENABLE_PPI_TASK \
	(((HAL_SW_SWITCH_GROUP_TASK_ENABLE_PPI << \
			DPPIC_SUBSCRIBE_CHG_EN_CHIDX_Pos) \
		&	DPPIC_SUBSCRIBE_CHG_EN_CHIDX_Msk) | \
	((DPPIC_SUBSCRIBE_CHG_EN_EN_Enabled << \
		DPPIC_SUBSCRIBE_CHG_EN_EN_Pos) \
		& DPPIC_SUBSCRIBE_CHG_EN_EN_Msk))

/* Enable Radio on SW Switch timer event.
 * Wire a SW SWITCH TIMER EVENTS_COMPARE[<cc_offset>] event
 * to a RADIO Enable task (TX or RX).
 *
 * Note:
 * We use the same PPI as for disabling the SW Switch PPI groups,
 * since we need to listen for the same event (SW Switch event).
 *
 * We use the same PPI for the alternative SW Switch Timer compare
 * event.
 */
#define HAL_SW_SWITCH_RADIO_ENABLE_PPI(index) \
	(HAL_SW_SWITCH_RADIO_ENABLE_PPI_BASE + (index))

#define HAL_SW_SWITCH_RADIO_ENABLE_S2_PPI(index) \
	(HAL_SW_SWITCH_RADIO_ENABLE_S2_PPI_BASE + (index))

#define HAL_SW_SWITCH_RADIO_ENABLE_PPI_REGISTER_EVT(cc_offset) \
	SW_SWITCH_TIMER->PUBLISH_COMPARE[cc_offset]
#define HAL_SW_SWITCH_RADIO_ENABLE_PPI_EVT(chan) \
	(((chan << TIMER_PUBLISH_COMPARE_CHIDX_Pos) \
		& TIMER_PUBLISH_COMPARE_CHIDX_Msk) | \
	((TIMER_PUBLISH_COMPARE_EN_Enabled << TIMER_PUBLISH_COMPARE_EN_Pos) \
		& TIMER_PUBLISH_COMPARE_EN_Msk))
#define HAL_SW_SWITCH_RADIO_ENABLE_PPI_REGISTER_TASK_TX \
	NRF_RADIO->SUBSCRIBE_TXEN
#define HAL_SW_SWITCH_RADIO_ENABLE_PPI_REGISTER_TASK_RX \
	NRF_RADIO->SUBSCRIBE_RXEN
#define HAL_SW_SWITCH_RADIO_ENABLE_PPI_TASK_TX_SET(chan) \
	(((chan << RADIO_SUBSCRIBE_TXEN_CHIDX_Pos) \
		& RADIO_SUBSCRIBE_TXEN_CHIDX_Msk) | \
	((RADIO_SUBSCRIBE_TXEN_EN_Enabled << \
			RADIO_SUBSCRIBE_TXEN_EN_Pos) \
		& RADIO_SUBSCRIBE_TXEN_EN_Msk))
#define HAL_SW_SWITCH_RADIO_ENABLE_PPI_TASK_RX_SET(chan) \
	(((chan << RADIO_SUBSCRIBE_RXEN_CHIDX_Pos) \
		&	RADIO_SUBSCRIBE_RXEN_CHIDX_Msk) | \
	((RADIO_SUBSCRIBE_RXEN_EN_Enabled << RADIO_SUBSCRIBE_RXEN_EN_Pos) \
		&	RADIO_SUBSCRIBE_RXEN_EN_Msk))

/* Cancel the SW switch timer running considering S8 timing:
 * wire the RADIO EVENTS_RATEBOOST event to SW_SWITCH_TIMER TASKS_CAPTURE task.
 *
 * Note: We already have a PPI where we publish the RATEBOOST event.
 */
#define HAL_SW_SWITCH_TIMER_S8_DISABLE_PPI_REGISTER_EVT \
	NRF_RADIO->PUBLISH_RATEBOOST
#define HAL_SW_SWITCH_TIMER_S8_DISABLE_PPI_EVT \
	(((HAL_SW_SWITCH_TIMER_S8_DISABLE_PPI << \
		RADIO_PUBLISH_RATEBOOST_CHIDX_Pos) \
	& RADIO_PUBLISH_RATEBOOST_CHIDX_Msk) | \
	((RADIO_PUBLISH_RATEBOOST_EN_Enabled << \
		RADIO_PUBLISH_RATEBOOST_EN_Pos) \
	& RADIO_PUBLISH_RATEBOOST_EN_Msk))
#define HAL_SW_SWITCH_TIMER_S8_DISABLE_PPI_REGISTER_TASK(cc_reg) \
	SW_SWITCH_TIMER->SUBSCRIBE_CAPTURE[cc_reg]
#define HAL_SW_SWITCH_TIMER_S8_DISABLE_PPI_TASK \
	(((HAL_SW_SWITCH_TIMER_S8_DISABLE_PPI << \
		TIMER_SUBSCRIBE_CAPTURE_CHIDX_Pos) \
		& TIMER_SUBSCRIBE_CAPTURE_CHIDX_Msk) | \
	((TIMER_SUBSCRIBE_CAPTURE_EN_Enabled << \
		TIMER_SUBSCRIBE_CAPTURE_EN_Pos) \
		& TIMER_SUBSCRIBE_CAPTURE_EN_Msk))

#if defined(CONFIG_BT_CTLR_DF_PHYEND_OFFSET_COMPENSATION_ENABLE)
/* The 2 adjacent TIMER EVENTS_COMPARE event offsets used for implementing PHYEND delay compensation
 * for SW_SWITCH_TIMER-based TIFS auto-switch. 'index' must be 0 or 1.
 */
#define SW_SWITCH_TIMER_PHYEND_DELAY_COMPENSATION_EVTS_COMP(index) \
	(SW_SWITCH_TIMER_EVTS_COMP_PHYEND_DELAY_COMPENSATION_BASE + (index))
#define HAL_SW_SWITCH_RADIO_ENABLE_PHYEND_DELAY_COMPENSATION_PPI(index) \
	HAL_SW_SWITCH_GROUP_TASK_DISABLE_PPI(index)
/* Cancel the SW switch timer running considering PHYEND delay compensation timing:
 * wire the RADIO EVENTS_CTEPRESENT event to SW_SWITCH_TIMER TASKS_CAPTURE task.
 */
#define HAL_SW_SWITCH_TIMER_PHYEND_DELAY_COMPENSATION_DISABLE_PPI 16
#define HAL_SW_SWITCH_TIMER_PHYEND_DELAY_COMPENSATION_DISABLE_PPI_REGISTER_EVT \
	NRF_RADIO->PUBLISH_CTEPRESENT

#define HAL_SW_SWITCH_TIMER_PHYEND_DELAY_COMPENSATION_DISABLE_PPI_EVT \
	(((HAL_SW_SWITCH_TIMER_PHYEND_DELAY_COMPENSATION_DISABLE_PPI \
	   << RADIO_PUBLISH_CTEPRESENT_CHIDX_Pos) & \
	  RADIO_PUBLISH_CTEPRESENT_CHIDX_Msk) | \
	 ((RADIO_PUBLISH_CTEPRESENT_EN_Enabled << RADIO_PUBLISH_CTEPRESENT_EN_Pos) & \
	  RADIO_PUBLISH_CTEPRESENT_EN_Msk))

#define HAL_SW_SWITCH_TIMER_PHYEND_DELAY_COMPENSATION_DISABLE_PPI_REGISTER_TASK(cc_reg) \
	SW_SWITCH_TIMER->SUBSCRIBE_CAPTURE[cc_reg]

#define HAL_SW_SWITCH_TIMER_PHYEND_DELAY_COMPENSATION_DISABLE_PPI_TASK \
	(((HAL_SW_SWITCH_TIMER_PHYEND_DELAY_COMPENSATION_DISABLE_PPI \
	   << TIMER_SUBSCRIBE_CAPTURE_CHIDX_Pos) & \
	  TIMER_SUBSCRIBE_CAPTURE_CHIDX_Msk) | \
	 ((TIMER_SUBSCRIBE_CAPTURE_EN_Enabled << TIMER_SUBSCRIBE_CAPTURE_EN_Pos) & \
	  TIMER_SUBSCRIBE_CAPTURE_EN_Msk))

#endif /* CONFIG_BT_CTLR_DF_PHYEND_OFFSET_COMPENSATION_ENABLE */

static inline void hal_radio_sw_switch_setup(
		uint8_t compare_reg,
		uint8_t radio_enable_ppi,
		uint8_t ppi_group_index)
{
	/* Set up software switch mechanism for next Radio switch. */

	/* Wire RADIO END event to PPI Group[<index>] enable task,
	 * over PPI[<HAL_SW_SWITCH_GROUP_TASK_ENABLE_PPI>]
	 */
	HAL_SW_SWITCH_GROUP_TASK_ENABLE_PPI_REGISTER_EVT =
	    HAL_SW_SWITCH_GROUP_TASK_ENABLE_PPI_EVT;
	HAL_SW_SWITCH_GROUP_TASK_ENABLE_PPI_REGISTER_TASK(ppi_group_index) =
	    HAL_SW_SWITCH_GROUP_TASK_ENABLE_PPI_TASK;

	/* We need to un-subscribe the other group from the PPI channel. */
	HAL_SW_SWITCH_GROUP_TASK_ENABLE_PPI_REGISTER_TASK(
		(ppi_group_index + 1) & 0x01) = 0;

	/* Wire SW Switch timer event <compare_reg> to the
	 * PPI[<radio_enable_ppi>] for enabling Radio. Do
	 * not wire the task; it is done by the caller of
	 * the function depending on the desired direction
	 * (TX/RX).
	 */
	HAL_SW_SWITCH_RADIO_ENABLE_PPI_REGISTER_EVT(compare_reg) =
		HAL_SW_SWITCH_RADIO_ENABLE_PPI_EVT(radio_enable_ppi);
}

static inline void hal_radio_txen_on_sw_switch(uint8_t ppi)
{
	nrf_radio_subscribe_set(NRF_RADIO, NRF_RADIO_TASK_TXEN, ppi);
}

static inline void hal_radio_b2b_txen_on_sw_switch(uint8_t ppi)
{
	/* NOTE: Calling radio_tmr_start/radio_tmr_start_us/radio_tmr_start_now
	 *       after the radio_switch_complete_and_b2b_tx() call would have
	 *       changed the PPI channel to HAL_RADIO_ENABLE_ON_TICK_PPI as we
	 *       cannot double buffer the subscribe buffer. Hence, lets have
	 *       both DPPI channel enabled (other one was enabled by the DPPI
	 *       group when the Radio End occurred) so that when both timer
	 *       trigger one of the DPPI is correct in the radio tx
	 *       subscription.
	 */
	nrf_radio_subscribe_set(NRF_RADIO, NRF_RADIO_TASK_TXEN, ppi);
	nrf_dppi_channels_enable(NRF_DPPIC, BIT(ppi));
}

static inline void hal_radio_rxen_on_sw_switch(uint8_t ppi)
{
	nrf_radio_subscribe_set(NRF_RADIO, NRF_RADIO_TASK_RXEN, ppi);
}

static inline void hal_radio_b2b_rxen_on_sw_switch(uint8_t ppi)
{
	/* NOTE: Calling radio_tmr_start/radio_tmr_start_us/radio_tmr_start_now
	 *       after the radio_switch_complete_and_b2b_rx() call would have
	 *       changed the PPI channel to HAL_RADIO_ENABLE_ON_TICK_PPI as we
	 *       cannot double buffer the subscribe buffer. Hence, lets have
	 *       both DPPI channel enabled (other one was enabled by the DPPI
	 *       group when the Radio End occurred) so that when both timer
	 *       trigger one of the DPPI is correct in the radio rx
	 *       subscription.
	 */
	nrf_radio_subscribe_set(NRF_RADIO, NRF_RADIO_TASK_RXEN, ppi);
	nrf_dppi_channels_enable(NRF_DPPIC, BIT(ppi));
}

static inline void hal_radio_sw_switch_disable(void)
{
	/* We cannot deactivate the PPI channels, as other tasks
	 * are subscribed to RADIO_END event, i.e on the same channel.
	 * So we simply cancel the task subscription.
	 */
	nrf_timer_subscribe_clear(SW_SWITCH_TIMER, NRF_TIMER_TASK_CLEAR);
	HAL_SW_SWITCH_GROUP_TASK_ENABLE_PPI_REGISTER_TASK(0) = 0;
	HAL_SW_SWITCH_GROUP_TASK_ENABLE_PPI_REGISTER_TASK(1) = 0;
}

static inline void hal_radio_sw_switch_cleanup(void)
{
	hal_radio_sw_switch_disable();
	nrf_dppi_channels_disable(NRF_DPPIC,
				  (BIT(HAL_SW_SWITCH_TIMER_CLEAR_PPI) |
				   BIT(HAL_SW_SWITCH_GROUP_TASK_ENABLE_PPI)));
	nrf_dppi_group_disable(NRF_DPPIC, SW_SWITCH_TIMER_TASK_GROUP(0));
	nrf_dppi_group_disable(NRF_DPPIC, SW_SWITCH_TIMER_TASK_GROUP(1));
}

static inline void hal_radio_sw_switch_coded_tx_config_set(uint8_t ppi_en,
	uint8_t ppi_dis, uint8_t cc_s2, uint8_t group_index)
{
	/* Publish the SW Switch Timer Compare event for S2 timing
	 * to the PPI that will be used to trigger Radio enable.
	 */
	HAL_SW_SWITCH_RADIO_ENABLE_PPI_REGISTER_EVT(cc_s2) =
		HAL_SW_SWITCH_RADIO_ENABLE_PPI_EVT(ppi_en);

	/* The Radio Enable Task is already subscribed to the channel. */

	/* Wire the Group task disable to the S2 EVENTS_COMPARE. */
	HAL_SW_SWITCH_GROUP_TASK_DISABLE_PPI_REGISTER_EVT(cc_s2) =
		HAL_SW_SWITCH_GROUP_TASK_DISABLE_PPI_EVT(ppi_dis);

	HAL_SW_SWITCH_GROUP_TASK_DISABLE_PPI_REGISTER_TASK(group_index) =
		HAL_SW_SWITCH_GROUP_TASK_DISABLE_PPI_TASK(ppi_dis);

	/* Capture CC to cancel the timer that has assumed
	 * S8 reception, if packet will be received in S2.
	 */
	HAL_SW_SWITCH_TIMER_S8_DISABLE_PPI_REGISTER_EVT =
		HAL_SW_SWITCH_TIMER_S8_DISABLE_PPI_EVT;
	HAL_SW_SWITCH_TIMER_S8_DISABLE_PPI_REGISTER_TASK(
		SW_SWITCH_TIMER_EVTS_COMP(group_index)) =
		HAL_SW_SWITCH_TIMER_S8_DISABLE_PPI_TASK;

	nrf_dppi_channels_enable(NRF_DPPIC,
				 BIT(HAL_SW_SWITCH_TIMER_S8_DISABLE_PPI));
}

static inline void hal_radio_sw_switch_coded_config_clear(uint8_t ppi_en,
	uint8_t ppi_dis, uint8_t cc_reg, uint8_t group_index)
{
	/* Invalidate subscription of S2 timer Compare used when
	 * RXing on LE Coded PHY.
	 *
	 * Note: we do not un-subscribe the Radio enable task because
	 * we use the same PPI for both SW Switch Timer compare events.
	 */
	HAL_SW_SWITCH_RADIO_ENABLE_PPI_REGISTER_EVT(
		SW_SWITCH_TIMER_S2_EVTS_COMP(group_index)) = 0;
}

static inline void hal_radio_sw_switch_disable_group_clear(uint8_t ppi_dis, uint8_t cc_reg,
							   uint8_t group_index)
{
	/* Wire the Group[group_index] task disable to the default
	 * SW Switch Timer EVENTS_COMPARE.
	 */
	HAL_SW_SWITCH_GROUP_TASK_DISABLE_PPI_REGISTER_EVT(
		cc_reg) =
		HAL_SW_SWITCH_GROUP_TASK_DISABLE_PPI_EVT(
			ppi_dis);
	HAL_SW_SWITCH_GROUP_TASK_DISABLE_PPI_REGISTER_TASK(
		group_index) =
		HAL_SW_SWITCH_GROUP_TASK_DISABLE_PPI_TASK(
			ppi_dis);
}

static inline void hal_radio_sw_switch_ppi_group_setup(void)
{
	/* Include the appropriate PPI channels in the two PPI Groups, used for
	 * SW-based TIFS.
	 *
	 * Note that this needs to be done before any SUBSCRIBE task
	 * registers are written, therefore, we clear the task registers
	 * here.
	 */
	NRF_DPPIC->SUBSCRIBE_CHG[SW_SWITCH_TIMER_TASK_GROUP(0)].EN = 0;
	NRF_DPPIC->SUBSCRIBE_CHG[SW_SWITCH_TIMER_TASK_GROUP(0)].DIS = 0;
	NRF_DPPIC->SUBSCRIBE_CHG[SW_SWITCH_TIMER_TASK_GROUP(1)].EN = 0;
	NRF_DPPIC->SUBSCRIBE_CHG[SW_SWITCH_TIMER_TASK_GROUP(1)].DIS = 0;

	NRF_DPPIC->TASKS_CHG[SW_SWITCH_TIMER_TASK_GROUP(0)].DIS = 1;
	NRF_DPPIC->TASKS_CHG[SW_SWITCH_TIMER_TASK_GROUP(1)].DIS = 1;

	/* Include the appropriate PPI channels in the two PPI Groups. */
	NRF_DPPIC->CHG[SW_SWITCH_TIMER_TASK_GROUP(0)] =
		BIT(HAL_SW_SWITCH_GROUP_TASK_DISABLE_PPI(0)) |
		BIT(HAL_SW_SWITCH_RADIO_ENABLE_PPI(0));
	NRF_DPPIC->CHG[SW_SWITCH_TIMER_TASK_GROUP(1)] =
		BIT(HAL_SW_SWITCH_GROUP_TASK_DISABLE_PPI(1)) |
		BIT(HAL_SW_SWITCH_RADIO_ENABLE_PPI(1));

	/* Sanity build-time check that RADIO Enable and Group Disable
	 * tasks are going to be subscribed on the same PPIs.
	 */
	BUILD_ASSERT(
		HAL_SW_SWITCH_GROUP_TASK_DISABLE_PPI_BASE ==
		HAL_SW_SWITCH_RADIO_ENABLE_PPI_BASE,
		"Radio enable and Group disable not on the same PPI channels.");

	/* Address nRF5340 Engineering A Errata 16 */
	nrf_radio_subscribe_clear(NRF_RADIO, NRF_RADIO_TASK_TXEN);
	nrf_radio_subscribe_clear(NRF_RADIO, NRF_RADIO_TASK_RXEN);
}

static inline void hal_radio_group_task_disable_ppi_setup(void)
{

	/* Wire SW SWITCH TIMER EVENTS COMPARE event <cc index-0> to
	 * PPI Group TASK [<index-0>] DISABLE task, over PPI<index-0>.
	 */
	HAL_SW_SWITCH_GROUP_TASK_DISABLE_PPI_REGISTER_EVT(
		SW_SWITCH_TIMER_EVTS_COMP(0)) =
		HAL_SW_SWITCH_GROUP_TASK_DISABLE_PPI_EVT(
			HAL_SW_SWITCH_GROUP_TASK_DISABLE_PPI(0));
	HAL_SW_SWITCH_GROUP_TASK_DISABLE_PPI_REGISTER_TASK(0) =
			HAL_SW_SWITCH_GROUP_TASK_DISABLE_PPI_TASK(
				HAL_SW_SWITCH_GROUP_TASK_DISABLE_PPI(0));

	/* Wire SW SWITCH TIMER event <compare index-1> to
	 * PPI Group[<index-1>] Disable Task, over PPI<index-1>.
	 */
	HAL_SW_SWITCH_GROUP_TASK_DISABLE_PPI_REGISTER_EVT(
		SW_SWITCH_TIMER_EVTS_COMP(1)) =
		HAL_SW_SWITCH_GROUP_TASK_DISABLE_PPI_EVT(
			HAL_SW_SWITCH_GROUP_TASK_DISABLE_PPI(1));
	HAL_SW_SWITCH_GROUP_TASK_DISABLE_PPI_REGISTER_TASK(1) =
			HAL_SW_SWITCH_GROUP_TASK_DISABLE_PPI_TASK(
				HAL_SW_SWITCH_GROUP_TASK_DISABLE_PPI(1));
}

#if defined(CONFIG_BT_CTLR_DF_PHYEND_OFFSET_COMPENSATION_ENABLE)
/**
 * @brief Setup additional EVENTS_COMPARE to compensate EVENTS_PHYEND delay.
 *
 * When EVENTS_PHYEND event is used to mark actual end of PDU, CTEINLINE is enabled but received
 * PDU does not include CTE after CRC, the EVENTS_PHYEND will be generated with a short delay.
 * That influences maintenance of TISF by software switch. To compensate the delay additional
 * EVENTS_COMPARE events is set with TIFS value subtracted by the delay. This EVENT_COMPARE
 * event will timeout before regular EVENTS_COMPARE and start radio switching procedure.
 * In case there is a CTEInfo in the received PDU, an EVENTS_CTEPRESENT will be generated by
 * Radio peripheral. The EVENTS_CTEPRESENT event is wired to cancel EVENTS_COMPARE setup for
 * handling delayed EVENTS_PHYEND.
 *
 * Disable of the group of PPIs responsbile for handling of software based switch is done by
 * timeout of regular EVENTS_PHYEND event. The EVENTS_PHYEND delay is short enough (16 us) that
 * the same EVENT COMPARE may be used to trigger disable task for the sotfware switch group.
 * In case the EVENTS_COMPARE for delayed EVENTS_PHYEND event timeouts, the group will be disabled
 * within the Radio TX rampup period.
 *
 * CTEINLINE is enabled only for reception of PDUs that may include Constant Tone Extension.
 * Delayed PHYEND event may occur only at end of received PDU, hence next task that is
 * triggered by compensated EVENTS_COMPARE is Radio TASKS_TXEN.
 *
 * @param phyend_delay_cc  Index of EVENTS_COMPARE event to be set for delayed EVENTS_PHYEND event
 * @param radio_enable_ppi Index of PPI to wire EVENTS_PHYEND event to Radio enable TX task.
 */
static inline void
hal_radio_sw_switch_phyend_delay_compensation_config_set(uint8_t radio_enable_ppi,
							 uint8_t phyend_delay_cc)
{
	/* Wire EVENTS_COMPARE[<phyend_delay_cc_offs>] event to Radio TASKS_TXEN */
	HAL_SW_SWITCH_RADIO_ENABLE_PPI_REGISTER_EVT(phyend_delay_cc) =
		HAL_SW_SWITCH_RADIO_ENABLE_PPI_EVT(radio_enable_ppi);

	/* The Radio Enable Task is already subscribed to the channel.
	 * There is no need to call channel enable again here.
	 */

	/* Wire Radio CTEPRESENT event to cancel EVENTS_COMPARE[<cc_offs>] timer */
	HAL_SW_SWITCH_TIMER_PHYEND_DELAY_COMPENSATION_DISABLE_PPI_REGISTER_EVT =
		HAL_SW_SWITCH_TIMER_PHYEND_DELAY_COMPENSATION_DISABLE_PPI_EVT;
	HAL_SW_SWITCH_TIMER_PHYEND_DELAY_COMPENSATION_DISABLE_PPI_REGISTER_TASK(phyend_delay_cc) =
		HAL_SW_SWITCH_TIMER_PHYEND_DELAY_COMPENSATION_DISABLE_PPI_TASK;

	/*  Enable CTEPRESENT event to disable EVENTS_COMPARE[<cc_offs>] PPI channel */
	nrf_dppi_channels_enable(NRF_DPPIC,
				 BIT(HAL_SW_SWITCH_TIMER_PHYEND_DELAY_COMPENSATION_DISABLE_PPI));
}

/**
 * @brief Clear additional EVENTS_COMAPRE responsible for compensation EVENTS_PHYEND delay.
 *
 * Disables PPI responsible for cancel of EVENTS_COMPARE set for delayed EVENTS_PHYEND.
 * Removes wiring of delayed EVENTS_COMPARE event to enable Radio TX task.
 *
 * @param phyend_delay_cc  Index of EVENTS_COMPARE event to be cleared
 * @param radio_enable_ppi Index of PPI to wire EVENTS_PHYEND event to Radio enable TX task.
 */
static inline void
hal_radio_sw_switch_phyend_delay_compensation_config_clear(uint8_t radio_enable_ppi,
							   uint8_t phyend_delay_cc)
{
	/* Invalidate PPI used for compensation of delayed EVETNS_PHYEND.
	 *
	 * Note: we do not un-subscribe the Radio enable task because
	 * we use the same PPI for both SW Switch Timer compare events.
	 */
	HAL_SW_SWITCH_RADIO_ENABLE_PPI_REGISTER_EVT(phyend_delay_cc) = NRF_PPI_NONE;

	HAL_SW_SWITCH_TIMER_PHYEND_DELAY_COMPENSATION_DISABLE_PPI_REGISTER_TASK(phyend_delay_cc) =
		NRF_PPI_NONE;

	/* Disable CTEPRESENT event to disable EVENTS_COMPARE[<phyend_delay_cc_offs>] PPI channel */
	nrf_dppi_channels_disable(NRF_DPPIC,
				  BIT(HAL_SW_SWITCH_TIMER_PHYEND_DELAY_COMPENSATION_DISABLE_PPI));
}
#endif /* CONFIG_BT_CTLR_DF_PHYEND_OFFSET_COMPENSATION_ENABLE */

#endif /* !CONFIG_BT_CTLR_TIFS_HW */

#endif /* CONFIG_SOC_NRF5340_CPUNET || DPPI_PRESENT */
