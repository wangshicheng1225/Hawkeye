/*
 * Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION &
 * AFFILIATES (the "Company") and all right, title, and interest in and to the
 * software product, including all associated intellectual property rights, are
 * and shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

#ifndef RTT_TEMPLATE_H
#define RTT_TEMPLATE_H

#define MAX_NB_FLOWS 16

/*
 * Entry point to rtt template (example) user algorithm (reference code)
 * This function starts the algorithm code of a single event for the rtt template example algorithm
 * It calculates the new rate parameters based on flow context data and event info.
 *
 * @event [in]: A pointer to an event data structure to be passed to extractor functions
 * @param [in]: A pointer to an array of parameters that are used to control algo behavior (see PPCC access register)
 * @counter [in/out]: A pointer to an array of counters that are incremented by algo (see PPCC access register)
 * @algo_ctxt [in/out]: A pointer to a flow context data retrieved by libpcc.
 * @results [out]: A pointer to result struct to update rate in HW.
 */
void rtt_template_algo(doca_pcc_dev_event_t *event,
		       uint32_t *param,
		       uint32_t *counter,
		       doca_pcc_dev_algo_ctxt_t *algo_ctxt,
		       doca_pcc_dev_results_t *results);

/*
 * Entry point to rtt template (example) user algorithm initialization (reference code)
 * This function starts the user algorithm initialization code
 * The function will be called once per process load and should init all ports
 *
 * @algo_idx [in]: Algo identifier. To be passed on to initialization APIs
 */
void rtt_template_init(uint32_t algo_idx);

/*
 * Entry point to rtt template (example) user algorithm setting parameters (reference code)
 * This function starts the user algorithm setting parameters code
 * The function will be called to update algorithm parameters
 *
 * @param_id_base [in]: id of the first parameter that was changed.
 * @param_num [in]: number of all parameters that were changed
 * @new_param_values [in]: pointer to an array which holds param_num number of new values for parameters
 * @params [in]: pointer to an array which holds beginning of the current parameters to be changed
 * @return: DOCA_PCC_DEV_STATUS_FAIL if input parameters (one or more) are not legal.
 */
doca_pcc_dev_error_t rtt_template_set_algo_params(uint32_t param_id_base,
						  uint32_t param_num,
						  const uint32_t *new_param_values,
						  uint32_t *params);

#ifdef DOCA_PCC_SAMPLE_TX_BYTES
/**
 * @brief return the last port utilization
 *
 * @port [in]: physical port number as appears in the cc event
 * @return: port utilization in 16 bit FXP number
 */
FORCE_INLINE uint32_t rtt_get_last_tx_port_util(uint32_t port)
{
	extern uint32_t g_utilized_bw[];
	return g_utilized_bw[port];
}
#endif

#endif /* RTT_TEMPLATE_H */
