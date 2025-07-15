/*
 * Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
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

#include <doca_pcc_np_dev.h>

#define NUM_AVAILABLE_PORTS (4)

/**< Counters IDs to configure and read from */
uint32_t counter_ids[NUM_AVAILABLE_PORTS] = {DOCA_PCC_DEV_NIC_COUNTER_PORT0_RX_BYTES,
					     DOCA_PCC_DEV_NIC_COUNTER_PORT1_RX_BYTES,
					     DOCA_PCC_DEV_NIC_COUNTER_PORT2_RX_BYTES,
					     DOCA_PCC_DEV_NIC_COUNTER_PORT3_RX_BYTES};
/**< Table of RX bytes counters to sample to */
uint32_t current_sampled_rx_bytes[NUM_AVAILABLE_PORTS] = {0};
/**< Port ID used to query rx counters */
uint32_t port_id = 0;
/**< Flag to indicate that the counters have been initiated */
uint32_t counters_started = 0;
/**< Flag to indicate that the mailbox operation has completed */
uint32_t mailbox_done = 0;

static uint16_t ntohs(uint16_t x) {
	return (((x & 0xff) << 8) | (x >> 8));
}

__attribute__((unused)) static inline void print_packet_header(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port) {
	doca_pcc_dev_printf("\nstart to print packet header\n");

	doca_pcc_dev_printf("src ip is: ");
	for(int i = 0; i < 4; i++)
		doca_pcc_dev_printf("%d%c", ((uint8_t *)(&src_ip))[i], i < 3 ? '.' : '\n');

	doca_pcc_dev_printf("dst ip is: ");
	for(int i = 0; i < 4; i++)
		doca_pcc_dev_printf("%d%c", ((uint8_t *)(&dst_ip))[i], i < 3 ? '.' : '\n');

	doca_pcc_dev_printf("src port is: %d\n", src_port);
	doca_pcc_dev_printf("dst port is: %d\n", dst_port);

	doca_pcc_dev_printf("finished to print packet header\n");
	doca_pcc_dev_trace_flush();
}


doca_pcc_dev_error_t doca_pcc_dev_np_user_packet_handler(struct doca_pcc_np_dev_request_packet *in,
							 struct doca_pcc_np_dev_response_packet *out)
{
	if (doca_pcc_dev_thread_rank() == 0 && counters_started == 0) {
		/* Configure counters to read */
		doca_pcc_dev_nic_counters_config(counter_ids, NUM_AVAILABLE_PORTS, current_sampled_rx_bytes);
		counters_started = 1;
		__dpa_thread_fence(__DPA_MEMORY, __DPA_W, __DPA_W);
	}
	// uint32_t *send_ts_p = (uint32_t *)(out->data);
	// uint32_t *rx_256_bytes_p = (uint32_t *)(out->data + 4);
	// uint32_t *rx_ts_p = (uint32_t *)(out->data + 8);

	// if (counters_started && mailbox_done) {
	// 	*send_ts_p = *((uint32_t *)(doca_pcc_np_dev_get_payload(in)));
	// 	doca_pcc_dev_nic_counters_sample();
	// 	*rx_256_bytes_p = current_sampled_rx_bytes[port_id];
	// 	*rx_ts_p = doca_pcc_dev_get_timer_lo();
	// 	__dpa_thread_fence(__DPA_MEMORY, __DPA_W, __DPA_W);
	// }

	if(counters_started && mailbox_done) {
		uint8_t *payload = doca_pcc_np_dev_get_raw_packet(in);
		uint32_t src_ip = *(uint32_t *)(payload + 26);
		uint32_t dst_ip = *(uint32_t *)(payload + 30);
		uint16_t src_port = ntohs(*(uint16_t *)(payload + 34));
		uint16_t dst_port = ntohs(*(uint16_t *)(payload + 36));


		// print_packet_header(src_ip, dst_ip, src_port, dst_port);	
		*(uint32_t *)(out->data) = src_ip;
		*(uint32_t *)(out->data + 4) = dst_ip;
		*(uint16_t *)(out->data + 8) = src_port;
		*(uint16_t *)(out->data + 10) = dst_port;
  		__dpa_thread_fence(__DPA_MEMORY, __DPA_W, __DPA_W);
 	}

	return DOCA_PCC_DEV_STATUS_OK;
}

/*
 * Called when host sends a mailbox send request.
 * Used to save the physical port ID that was queried from the host.
 */
doca_pcc_dev_error_t doca_pcc_dev_user_mailbox_handle(void *request,
						      uint32_t request_size,
						      uint32_t max_response_size,
						      void *response,
						      uint32_t *response_size)
{
	if (request_size != sizeof(uint32_t))
		return DOCA_PCC_DEV_STATUS_FAIL;

	port_id = *(uint32_t *)(request);

	mailbox_done = 1;
	__dpa_thread_fence(__DPA_MEMORY, __DPA_W, __DPA_W);

	(void)(max_response_size);
	(void)(response);
	(void)(response_size);

	return DOCA_PCC_DEV_STATUS_OK;
}
