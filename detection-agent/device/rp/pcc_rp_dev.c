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

#include <doca_pcc_dev.h>
#include <doca_pcc_dev_event.h>
#include <doca_pcc_dev_algo_access.h>
#include "algo/rtt_template.h"
#include "utils.h"
#include "algo/rtt_template_ctxt.h"

#define __unused __attribute__((__unused__))
#define DOCA_PCC_DEV_EVNT_ROCE_ACK_MASK (1 << DOCA_PCC_DEV_EVNT_ROCE_ACK)
#define SAMPLER_THREAD_RANK (0)
#define COUNTERS_SAMPLE_WINDOW_IN_MICROSEC (10)
#define NUM_AVAILABLE_PORTS (4)

/**< Counters IDs to configure and read from */
uint32_t counter_ids[NUM_AVAILABLE_PORTS] = {DOCA_PCC_DEV_NIC_COUNTER_PORT0_TX_BYTES,
					     DOCA_PCC_DEV_NIC_COUNTER_PORT1_TX_BYTES,
					     DOCA_PCC_DEV_NIC_COUNTER_PORT2_TX_BYTES,
					     DOCA_PCC_DEV_NIC_COUNTER_PORT3_TX_BYTES};
/**< Table of TX bytes counters to sample to */
uint32_t current_sampled_tx_bytes[NUM_AVAILABLE_PORTS] = {0};
/**< Table of TX bytes counters that was last sampled */
uint32_t previous_sampled_tx_bytes[NUM_AVAILABLE_PORTS] = {0};
/**< Last timestamp of sampled counters */
uint32_t last_sample_ts;
/**< Ports active bandwidth. Units of MB/s */
uint32_t ports_bw[NUM_AVAILABLE_PORTS];
/**< Percentage of the current active ports utilized bandwidth. Saved in FXP 16 format */
uint32_t g_utilized_bw[NUM_AVAILABLE_PORTS];
/**< Flag to indicate that the mailbox operation has completed */
uint32_t mailbox_done = 0;

extern flow_meta flow_metas[MAX_NB_FLOWS];
#define GET_FLOW_INFO_OP 1


#ifdef DOCA_PCC_SAMPLE_TX_BYTES
/*
 * Calculate wrap around in case of int overflow.
 *
 * @greater_num [in]: greater int
 * @smaller_num [in]: smaller int
 * @return: difference with wrap around
 */
FORCE_INLINE uint32_t diff_with_wrap32(uint32_t greater_num, uint32_t smaller_num)
{
	uint32_t diff_res;

	if (unlikely(greater_num < smaller_num))
		diff_res = UINT32_MAX - smaller_num + greater_num + 1; /* wrap around */
	else
		diff_res = greater_num - smaller_num;
	return diff_res;
}

/*
 * Dedicate one thread to sample tx bytes counters on a defined time frame,
 * calculate current bandwidth and compare with maximum port bandwidth.
 * This call is enabled by user option to sample TX bytes counter
 */
FORCE_INLINE void thread0_calc_ports_utilization(void)
{
	uint32_t tx_bytes_delta[NUM_AVAILABLE_PORTS], current_bw[NUM_AVAILABLE_PORTS], ts_delta, current_ts;

	if ((doca_pcc_dev_thread_rank() == SAMPLER_THREAD_RANK) && mailbox_done) {
		current_ts = doca_pcc_dev_get_timer_lo();
		ts_delta = diff_with_wrap32(current_ts, last_sample_ts);
		if (ts_delta >= COUNTERS_SAMPLE_WINDOW_IN_MICROSEC) {
			doca_pcc_dev_nic_counters_sample();
			for (int i = 0; i < NUM_AVAILABLE_PORTS; i++) {
				tx_bytes_delta[i] =
					diff_with_wrap32(current_sampled_tx_bytes[i], previous_sampled_tx_bytes[i]);
				previous_sampled_tx_bytes[i] = current_sampled_tx_bytes[i];
				current_bw[i] =
					(doca_pcc_dev_fxp_mult(tx_bytes_delta[i], doca_pcc_dev_fxp_recip(ts_delta)) >>
					 16);
				g_utilized_bw[i] = (1 << 16);
				if (current_bw[i] < ports_bw[i])
					g_utilized_bw[i] = doca_pcc_dev_fxp_mult(current_bw[i],
										 doca_pcc_dev_fxp_recip(ports_bw[i]));
			}
			last_sample_ts = current_ts;
		}
	}
}

/*
 * Initialize TX counters sampling
 */
void tx_counters_sampling_init(void)
{
	/* Configure counters to read */
	doca_pcc_dev_nic_counters_config(counter_ids, NUM_AVAILABLE_PORTS, current_sampled_tx_bytes);
	/* Sample counters and save in global table */
	doca_pcc_dev_nic_counters_sample();
	last_sample_ts = doca_pcc_dev_get_timer_lo();
	/* Save sampled TX bytes */
	for (int i = 0; i < NUM_AVAILABLE_PORTS; i++)
		previous_sampled_tx_bytes[i] = current_sampled_tx_bytes[i];
}
#endif

/*
 * Main entry point to user CC algorithm (Refernce code)
 * This function starts the algorithm code of a single event
 * It receives the flow context data, the event info and outputs the new rate parameters
 * The function can support multiple algorithms and can call the per algorithm handler based on
 * the algo type. If a single algorithm is required this code can be simplified
 * The function can not be renamed as it is called by the handler infrastructure
 *
 * @algo_ctxt [in]: A pointer to a flow context data retrieved by libpcc.
 * @event [in]: A pointer to an event data structure to be passed to extractor functions
 * @attr [in]: A pointer to additional parameters (algo type).
 * @results [out]: A pointer to result struct to update rate in HW.
 */
void doca_pcc_dev_user_algo(doca_pcc_dev_algo_ctxt_t *algo_ctxt,
			    doca_pcc_dev_event_t *event,
			    const doca_pcc_dev_attr_t *attr,
			    doca_pcc_dev_results_t *results)
{
	uint32_t port_num = doca_pcc_dev_get_ev_attr(event).port_num;
	uint32_t *param = doca_pcc_dev_get_algo_params(port_num, attr->algo_slot);
	uint32_t *counter = doca_pcc_dev_get_counters(port_num, attr->algo_slot);

#ifdef DOCA_PCC_SAMPLE_TX_BYTES
	thread0_calc_ports_utilization();
#endif

 	/* Force to use custom cc algorithm */
	uint32_t algo_slot = attr->algo_slot == 0 ? attr->algo_slot : 0;
	switch (algo_slot) {
	case 0: {
		rtt_template_algo(event, param, counter, algo_ctxt, results);
		break;
	}
	default: {
		doca_pcc_dev_default_internal_algo(algo_ctxt, event, attr, results);
		break;
	}
	};
}

/*
 * Main entry point to user algorithm initialization (reference code)
 * This function starts the user algorithm initialization code
 * The function will be called once per process load and should init all supported
 * algorithms and all ports
 *
 * @disable_event_bitmask [out]: user code can tell the infrastructure which event
 * types to ignore (mask out). Events of this type will be dropped and not passed to
 * any algo
 */
void doca_pcc_dev_user_init(uint32_t *disable_event_bitmask)
{
	uint32_t algo_idx = 0;

	/* Initialize algorithm with algo_idx=0 */
	rtt_template_init(algo_idx);

	for (int port_num = 0; port_num < DOCA_PCC_DEV_MAX_NUM_PORTS; ++port_num) {
		/* Slot 0 will use algo_idx 0, default enabled */
		doca_pcc_dev_init_algo_slot(port_num, 0, algo_idx, 1);
		doca_pcc_dev_trace_5(0, port_num, 0, algo_idx, 1, DOCA_PCC_DEV_EVNT_ROCE_ACK_MASK);
	}

#ifdef DOCA_PCC_SAMPLE_TX_BYTES
	tx_counters_sampling_init();
#endif

	/* disable events of below type */
	*disable_event_bitmask = DOCA_PCC_DEV_EVNT_ROCE_ACK_MASK;
	doca_pcc_dev_printf("%s, disable_event_bitmask=0x%x\n", __func__, *disable_event_bitmask);
	doca_pcc_dev_trace_flush();
}

/*
 * Called when the parameter change was set externally.
 * The implementation should:
 *     Check the given new_parameters values. If those are correct from the algorithm perspective,
 *     assign them to the given parameter array.

 * @port_num [in]: index of the port
 * @algo_slot [in]: Algo slot identifier as reffered to in the PPCC command field "algo_slot"
 * if possible it should be equal to the algo_idx
 * @param_id_base [in]: id of the first parameter that was changed.
 * @param_num [in]: number of all parameters that were changed
 * @new_param_values [in]: pointer to an array which holds param_num number of new values for parameters
 * @params [in]: pointer to an array which holds beginning of the current parameters to be changed
 * @return -
 * DOCA_PCC_DEV_STATUS_OK: Parameters were set
 * DOCA_PCC_DEV_STATUS_FAIL: the values (one or more) are not legal. No parameters were changed
 */
doca_pcc_dev_error_t doca_pcc_dev_user_set_algo_params(uint32_t port_num,
						       uint32_t algo_slot,
						       uint32_t param_id_base,
						       uint32_t param_num,
						       const uint32_t *new_param_values,
						       uint32_t *params)
{
	/* Notify the user that a change happened to take action.
	 * I.E.: Pre calculate values to be used in the algo that are based on the parameter value.
	 * Support more complex checks. E.G.: Param is a bit mask - min and max do not help
	 * Param dependency checking.
	 */
	doca_pcc_dev_error_t ret = DOCA_PCC_DEV_STATUS_OK;

	switch (algo_slot) {
	case 0: {
		uint32_t algo_idx = doca_pcc_dev_get_algo_index(port_num, algo_slot);

		if (algo_idx == 0)
			ret = rtt_template_set_algo_params(param_id_base, param_num, new_param_values, params);
		else
			ret = DOCA_PCC_DEV_STATUS_FAIL;

		break;
	}
	default:
		break;
	}
	return ret;
}

/*
 * Called when host sends a mailbox send request.
 * Used to save the ports active bandwidth that was queried from the host.
 *
 * @request [in]: Pointer to the host request.
 * @request_size [in]: Memory size of the request from host.
 * @max_response_size [in]: Maximum response memory size that was on host.
 * @response [out]: Pointer to the device response.
 * @response_size [out]: Memory size of the response.
 * @return -
 * DOCA_PCC_DEV_STATUS_OK: Mailbox operation done successfully
 * DOCA_PCC_DEV_STATUS_FAIL: Error in mailbox operation
 */
doca_pcc_dev_error_t doca_pcc_dev_user_mailbox_handle(void *request,
						      uint32_t request_size,
						      uint32_t max_response_size,
						      void *response,
						      uint32_t *response_size)
{
	if (request_size != sizeof(uint32_t))
		return DOCA_PCC_DEV_STATUS_FAIL;

	uint32_t op_type = *(uint32_t *)(request);
	if (op_type == GET_FLOW_INFO_OP) {
		*(uint32_t *)response_size = sizeof(flow_metas);
		for(uint32_t i = 0; i < MAX_NB_FLOWS; i++) {
			flow_meta *tmp = (flow_meta *)response + i;
			tmp->flowtag = flow_metas[i].flowtag;
			tmp->src_ip = flow_metas[i].src_ip;
			tmp->dst_ip = flow_metas[i].dst_ip;
			tmp->src_port = flow_metas[i].src_port;
			tmp->dst_port = flow_metas[i].dst_port;
			tmp->rtt = flow_metas[i].rtt;
		}
	} else {
		uint32_t ports_active_bw = *(uint32_t *)(request);
		for (int i = 0; i < NUM_AVAILABLE_PORTS; i++)
		ports_bw[i] = ports_active_bw;
	}

	(void)(max_response_size);
	(void)(response);
	(void)(response_size);

	

	mailbox_done = 1;
	__dpa_thread_fence(__DPA_MEMORY, __DPA_W, __DPA_W);


	return DOCA_PCC_DEV_STATUS_OK;
}
