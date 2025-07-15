#include "headers.h"
#include "switch_config.h"

//extern "C" {
//}
#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_DATA(d) *((uint8_t *)&d + 5), *((uint8_t *)&d + 4), \
                    *((uint8_t *)&d + 3), *((uint8_t *)&d + 2), \
                    *((uint8_t *)&d + 1), *((uint8_t *)&d + 0)
#define CHECK_BF_STATUS(func_call)                  \
    do {                                            \
        bf_status = (func_call);                    \
        printf("DEBUG: " #func_call " returned %d\n", bf_status); \
        assert(bf_status == BF_SUCCESS);            \
    } while (0); \

const uint32_t REG_NUM = 1;
const double EXP_PERIOD = 10;
struct timespec cur, record_sync_time_start, record_sync_time_end;
    // obtain start time
    // clock_gettime(CLOCK_MONOTONIC, &start);
void calc_time_usage(const struct timespec* time_start, 
                     const struct timespec* time_end, 
                     const char *message)
{
         // calc time delta (s)
    long seconds = time_end->tv_sec - time_start->tv_sec;
    long nanoseconds = time_end->tv_nsec - time_start->tv_nsec;
    double elapsed = seconds + nanoseconds*1e-9;

    printf("%s: %.9f seconds.\n", message, elapsed);   

}


uint32_t ipv4AddrToUint32(const char* ip_str) {
  uint32_t ip_addr;
  if (inet_pton(AF_INET, ip_str, &ip_addr) != 1) {
      fprintf(stderr, "Error: Invalid IP address format.\n");
      return EXIT_FAILURE;
  }

  return ntohl(ip_addr);
  // return ip_addr;
}


// C-style using bf_pm
static void port_setup(const bf_rt_target_t *dev_tgt,
                       const switch_port_t *port_list,
                       const uint8_t port_count) {
    bf_status_t bf_status;

    // Add and enable ports
    for (unsigned int idx = 0; idx < port_count; idx++) {
        bf_pal_front_port_handle_t port_hdl;
        bf_status = bf_pm_port_str_to_hdl_get(dev_tgt->dev_id,
                                              port_list[idx].fp_port,
                                              &port_hdl);
        assert(bf_status == BF_SUCCESS);
        bf_status = bf_pm_port_add(dev_tgt->dev_id, &port_hdl,
                                   BF_SPEED_40G, BF_FEC_TYP_NONE);
        assert(bf_status == BF_SUCCESS);
        bf_status = bf_pm_port_enable(dev_tgt->dev_id, &port_hdl);
        assert(bf_status == BF_SUCCESS);
        printf("Port %s is enabled successfully!\n", port_list[idx].fp_port);
    }
}



static void switchd_setup(bf_switchd_context_t *switchd_ctx, const char *prog) {
	char conf_file[256];
	char bf_sysfs_fname[128] = "/sys/class/bf/bf0/device";
    FILE *fd;

	switchd_ctx->install_dir = strdup(getenv("SDE_INSTALL"));
	sprintf(conf_file, "%s%s%s%s", \
	        getenv("SDE_INSTALL"), "/share/p4/targets/tofino/", prog, ".conf");
	switchd_ctx->conf_file = conf_file;
	switchd_ctx->running_in_background = true;
	switchd_ctx->dev_sts_thread = true;
	switchd_ctx->dev_sts_port = 7777; // 9090?
	

//    switchd_ctx->kernel_pkt = true;
	// Determine if kernel mode packet driver is loaded 
    strncat(bf_sysfs_fname, "/dev_add",
            sizeof(bf_sysfs_fname) - 1 - strlen(bf_sysfs_fname));
    printf("bf_sysfs_fname %s\n", bf_sysfs_fname);
    fd = fopen(bf_sysfs_fname, "r");
    if (fd != NULL) {
        // override previous parsing if bf_kpkt KLM was loaded 
        printf("kernel mode packet driver present, forcing kpkt option!\n");
        switchd_ctx->kernel_pkt = true;
        fclose(fd);
    }

    assert(bf_switchd_lib_init(switchd_ctx) == BF_SUCCESS);
    printf("\nbf_switchd is initialized correctly!\n");
}

static void bfrt_setup(const bf_rt_target_t *dev_tgt,
                const bf_rt_info_hdl **bfrt_info,
                const char* prog,
               	bf_rt_session_hdl **session) {
  
 	bf_status_t bf_status;

    // Get bfrtInfo object from dev_id and p4 program name
    bf_status = bf_rt_info_get(dev_tgt->dev_id, prog, bfrt_info);
    assert(bf_status == BF_SUCCESS);
    // Create a session object
    bf_status = bf_rt_session_create(session);
    assert(bf_status == BF_SUCCESS);
    printf("bfrt_info is got and session is created correctly!\n"); 
//	return bf_status;
}


static void losslessTrafficSetUp(const bf_rt_target_t *dev_tgt,
							const switch_port_t* port_list,
							const uint8_t port_count) {
	bf_status_t bf_status;
	
	bf_dev_id_t dev_id = dev_tgt->dev_id; // 0
	uint32_t ppg_cell = 100;
	bf_tm_ppg_hdl  ppg_hdl;
	uint8_t icos_bmap = 0xff;//
	uint32_t skid_cells = 100;
	uint8_t cos_to_icos[8]={0,1,2,3,4,5,6,7}; 
	bf_tm_queue_t queue_id = 3;
	uint32_t queue_cells = 100;
	uint8_t queue_count = 8;
	uint8_t queue_mapping[8] = {0,1,2,3,4,5,6,7};
	
	for (uint8_t idx = 0; idx < port_count; idx ++) {
		// Step 1: Map lossless traffic to a PPG handle with a buffer limit

		bf_dev_port_t dev_port; 
		bf_status = bf_pm_port_str_to_dev_port_get(
            dev_id, (char *)port_list[idx].fp_port, &dev_port
        );		
		assert(bf_status == BF_SUCCESS);
		
		bf_status = bf_tm_ppg_allocate(dev_id, dev_port, &ppg_hdl);
		assert(bf_status == BF_SUCCESS);
		
		bf_status = bf_tm_ppg_guaranteed_min_limit_set(dev_id, 
														ppg_hdl, ppg_cell );
		assert(bf_status == BF_SUCCESS);
		// No dynmical buffering or pooling

		// Step 2: Map traffic to an iCoS
		bf_status = bf_tm_ppg_icos_mapping_set(dev_id, ppg_hdl, icos_bmap);
		assert(bf_status == BF_SUCCESS);
		
		// Step 3; Declare buffer and set up pause/PFC generation
		bf_status =	bf_tm_ppg_skid_limit_set(dev_id, ppg_hdl, skid_cells);
		assert(bf_status == BF_SUCCESS);
	
		bf_status = bf_tm_ppg_lossless_treatment_enable(dev_id,
	                                                	 ppg_hdl);
		assert(bf_status == BF_SUCCESS);
	
		// BF_TM_PAUSE_PORT  BF_TM_PAUSE_PFC
		bf_status = bf_tm_port_flowcontrol_mode_set(dev_id, dev_port, BF_TM_PAUSE_PORT);
		assert(bf_status == BF_SUCCESS);
		bf_status = bf_tm_port_pfc_cos_mapping_set(dev_id, dev_port, cos_to_icos);
		assert(bf_status == BF_SUCCESS);
		
		// Step 4: Apply Buffering
		for (uint8_t idx = 0; idx < queue_count; idx ++) {
			bf_status = bf_tm_q_guaranteed_min_limit_set(dev_id, dev_port, queue_mapping[idx], queue_cells);
			assert(bf_status == BF_SUCCESS);
		}		
		
		// Step 5: Allocate queues
		bf_status = bf_tm_port_q_mapping_set(dev_id, dev_port, queue_count, queue_mapping);
		assert(bf_status == BF_SUCCESS);

		// Step 7: Honor pause/PFC events
		
		for (uint8_t idx = 0; idx < queue_count; idx ++) {
			// queue idx has cos idx
			bf_status = bf_tm_q_pfc_cos_mapping_set(dev_id, dev_port, queue_mapping[idx], idx);
			assert(bf_status == BF_SUCCESS);
		}		
		assert(bf_status==BF_SUCCESS);	
		bf_status = bf_tm_port_flowcontrol_rx_set(dev_id, dev_port, BF_TM_PAUSE_PORT);
		assert(bf_status==BF_SUCCESS);
	
		bf_status = bf_pal_port_flow_control_link_pause_set(dev_id, dev_port, 1, 1 );
		assert(bf_status==BF_SUCCESS);
		bf_status = bf_pal_port_flow_control_pfc_set(dev_id, dev_port, 0xff, 0xff);
		//bf_status = bf_pal_port_flow_control_link_pause_set(dev_id, dev_port, 1, 1 );
		assert(bf_status==BF_SUCCESS);
	
		printf("Set up lossless for port %s and dev_port %u\n", port_list[idx].fp_port, dev_port);
	}

}

static void forward_2d_table_setup(const bf_rt_target_t *dev_tgt,
                                const bf_rt_info_hdl *bfrt_info,
                                const bf_rt_table_hdl **forward_table,
                                forward_2d_table_info_t *forward_table_info,
                                const forward_entry_t *forward_list,
                                const uint8_t forward_count) {
    bf_status_t bf_status;

    // Get table object from name
    bf_status = bf_rt_table_from_name_get(bfrt_info,
                                          "SwitchIngress.ti_2d_forward",
                                          forward_table);
    assert(bf_status == BF_SUCCESS);

    // Allocate key and data once, and use reset across different uses
    bf_status = bf_rt_table_key_allocate(*forward_table,
                                         &forward_table_info->key);
    assert(bf_status == BF_SUCCESS);
    bf_status = bf_rt_table_data_allocate(*forward_table,
                                          &forward_table_info->data);
    assert(bf_status == BF_SUCCESS);

    // Get field-ids for key field

	bf_status = bf_rt_key_field_id_get(*forward_table, "hdr.ipv4.dst_ip",
										&forward_table_info->kid_ipv4_dst_ip);
    assert(bf_status == BF_SUCCESS);

	bf_status = bf_rt_key_field_id_get(*forward_table, "ig_intr_md.ingress_port",
										&forward_table_info->kid_ingress_port);

    // Get action Ids for action a_unicast
    bf_status = bf_rt_action_name_to_id(*forward_table,
                                        "SwitchIngress.ai_unicast",
                                        &forward_table_info->aid_ai_unicast);
    assert(bf_status == BF_SUCCESS);

    // Get field-ids for data field
    bf_status = bf_rt_data_field_id_with_action_get(
        *forward_table, "port",
        forward_table_info->aid_ai_unicast, &forward_table_info->did_port
    );
    assert(bf_status == BF_SUCCESS);

    //                                       //
    // Set up the multicast for ai_broadcast //
    //                                       //
/*
    bf_status = bf_mc_create_session(&forward_table_info->mc_session);
    assert(bf_status == BF_SUCCESS);

    bf_status = bf_mc_mgrp_create(forward_table_info->mc_session,
                                  dev_tgt->dev_id,
                                  BROADCAST_MC_GID,
                                  &forward_table_info->mc_mgrp);
    assert(bf_status == BF_SUCCESS);

    BF_MC_PORT_MAP_INIT(forward_table_info->mc_port_map);
    BF_MC_LAG_MAP_INIT(forward_table_info->mc_lag_map);

    for (unsigned idx = 0; idx < forward_count; idx++) {
        bf_dev_port_t dev_port;
        bf_status = bf_pm_port_str_to_dev_port_get(
            dev_tgt->dev_id, (char *)forward_list[idx].fp_port, &dev_port
        );
        assert(bf_status == BF_SUCCESS);
        BF_MC_PORT_MAP_SET(forward_table_info->mc_port_map, dev_port);
    }

    // Rid set to 0
    bf_status = bf_mc_node_create(forward_table_info->mc_session,
                                  dev_tgt->dev_id, 0,
                                  forward_table_info->mc_port_map,
                                  forward_table_info->mc_lag_map,
                                  &forward_table_info->mc_node);
    assert(bf_status == BF_SUCCESS);

    bf_status = bf_mc_associate_node(forward_table_info->mc_session,
                                     dev_tgt->dev_id,
                                     forward_table_info->mc_mgrp,
                                     forward_table_info->mc_node,
                                     false,  0);
    assert(bf_status == BF_SUCCESS);

    bf_status = bf_mc_complete_operations(forward_table_info->mc_session);
    assert(bf_status == BF_SUCCESS);

    bf_status = bf_mc_destroy_session(forward_table_info->mc_session);
    assert(bf_status == BF_SUCCESS);
*/
}

static void forward_2d_table_entry_add(const bf_rt_target_t *dev_tgt,
                                    const bf_rt_session_hdl *session,
                                    const bf_rt_table_hdl *forward_table,
                                    forward_2d_table_info_t *forward_table_info,
                                    forward_2d_table_entry_t *forward_entry) {
    bf_status_t bf_status;

    // Reset key before use
    bf_rt_table_key_reset(forward_table, &forward_table_info->key);

    // Fill in the Key object
	bf_status = bf_rt_key_field_set_value(forward_table_info->key,
										  forward_table_info->kid_ipv4_dst_ip,
										  forward_entry->ipv4_addr); 
    assert(bf_status == BF_SUCCESS);
	
	bf_status = bf_rt_key_field_set_value(forward_table_info->key,
										  forward_table_info->kid_ingress_port,
										  forward_entry->ingress_port); 
    assert(bf_status == BF_SUCCESS);

    if (strcmp(forward_entry->action, "ai_unicast") == 0) {
        // Reset data before use
        bf_rt_table_action_data_reset(forward_table,
                                      forward_table_info->aid_ai_unicast,
                                      &forward_table_info->data);
        // Fill in the Data object
        bf_status = bf_rt_data_field_set_value(forward_table_info->data,
                                               forward_table_info->did_port,
                                               forward_entry->egress_port);
        assert(bf_status == BF_SUCCESS);
    }
//    else if (strcmp(forward_entry->action, "ai_broadcast") == 0) {
//        bf_rt_table_action_data_reset(forward_table,
//                                      forward_table_info->aid_broadcast,
//                                      &forward_table_info->data);
//    }

    // Call table entry add API
    bf_status = bf_rt_table_entry_add(forward_table, session, dev_tgt,
                                      forward_table_info->key,
                                      forward_table_info->data);
    assert(bf_status == BF_SUCCESS);
    bf_status = bf_rt_session_complete_operations(session);
    assert(bf_status == BF_SUCCESS);
}

static void forward_2d_table_deploy(const bf_rt_target_t *dev_tgt,
                                 const bf_rt_info_hdl *bfrt_info,
                                 const bf_rt_session_hdl *session,
                                 const forward_entry_t *forward_list,
                                 const uint8_t forward_count) {
    bf_status_t bf_status;
    const bf_rt_table_hdl *forward_table = NULL;
    forward_2d_table_info_t forward_table_info;

    // Set up the forward table
    forward_2d_table_setup(dev_tgt, bfrt_info, &forward_table,
                        &forward_table_info, forward_list, forward_count);
    printf("Table forward is set up correctly!\n");

    // Add forward entries
    for (unsigned int idx = 0; idx < forward_count; idx++) {

		forward_2d_table_entry_t forward_entry =  {
			.ingress_port = forward_list[idx].ingress_port,
			.ipv4_addr = ipv4AddrToUint32(forward_list[idx].ipv4_addr),
			.action = "ai_unicast",
			.egress_port = forward_list[idx].egress_port,
		}; 
//        bf_status = bf_pm_port_str_to_dev_port_get(
//            dev_tgt->dev_id,
//            (char *)forward_list[idx].fp_port, &forward_entry.egress_port
//        );
        forward_2d_table_entry_add(dev_tgt, session, forward_table,
                                &forward_table_info, &forward_entry);
//        printf("Add entry to unicast packets from port %lu with dstIP %s to port %lu\n",
//				forward_list[idx].ingress_port, forward_list[idx].ipv4_addr,
//                forward_list[idx].egress_port);
    }
    printf("Table forward is deployed  correctly!\n");

}


static void forward_polling_table_setup(const bf_rt_target_t *dev_tgt,
                                const bf_rt_info_hdl *bfrt_info,
                                const bf_rt_table_hdl **forward_table,
                                forward_polling_table_info_t *forward_table_info) {
    bf_status_t bf_status;

    // Get table object from name
    bf_status = bf_rt_table_from_name_get(bfrt_info,
                                          "SwitchIngress.ti_match_polling_TP",
                                          forward_table);
    assert(bf_status == BF_SUCCESS);

    // Allocate key and data once, and use reset across different uses
    bf_status = bf_rt_table_key_allocate(*forward_table,
                                         &forward_table_info->key);
    assert(bf_status == BF_SUCCESS);
    bf_status = bf_rt_table_data_allocate(*forward_table,
                                          &forward_table_info->data);
    assert(bf_status == BF_SUCCESS);

    // Get field-ids for key field

	bf_status = bf_rt_key_field_id_get(*forward_table, "hdr.polling.TP_type",
										&forward_table_info->kid_TP_type);
    assert(bf_status == BF_SUCCESS);

	bf_status = bf_rt_key_field_id_get(*forward_table, "hdr.polling.vf_dst_ip",
										&forward_table_info->kid_vf_dst_ip);
    assert(bf_status == BF_SUCCESS);

	bf_status = bf_rt_key_field_id_get(*forward_table, "ig_intr_md.ingress_port",
										&forward_table_info->kid_ingress_port);

    // Get action Ids for action a_unicast
    bf_status = bf_rt_action_name_to_id(*forward_table,
                                        "SwitchIngress.ai_unicast_polling",
                                        &forward_table_info->aid_ai_unicast);
    assert(bf_status == BF_SUCCESS);

    bf_status = bf_rt_action_name_to_id(*forward_table,
                                        "SwitchIngress.ai_broadcast_polling",
                                        &forward_table_info->aid_ai_broadcast);
    assert(bf_status == BF_SUCCESS);
    
	bf_status = bf_rt_action_name_to_id(*forward_table,
                                        "SwitchIngress.ai_drop_polling",
                                        &forward_table_info->aid_ai_drop);
    assert(bf_status == BF_SUCCESS);
    // Get field-ids for data field
    bf_status = bf_rt_data_field_id_with_action_get(
        *forward_table, "port",
        forward_table_info->aid_ai_unicast, &forward_table_info->did_unicast_port
    );
    assert(bf_status == BF_SUCCESS);

    bf_status = bf_rt_data_field_id_with_action_get(
        *forward_table, "port",
        forward_table_info->aid_ai_broadcast, &forward_table_info->did_broadcast_port
    );
    assert(bf_status == BF_SUCCESS);

    bf_status = bf_rt_data_field_id_with_action_get(
        *forward_table, "mc_grp_id",
        forward_table_info->aid_ai_broadcast, &forward_table_info->did_mc_grp_id
    );
    assert(bf_status == BF_SUCCESS);
}

static void forward_polling_table_entry_add(const bf_rt_target_t *dev_tgt,
                                    const bf_rt_session_hdl *session,
                                    const bf_rt_table_hdl *forward_table,
                                    forward_polling_table_info_t *forward_table_info,
                                    forward_polling_table_entry_t *forward_entry) {
    bf_status_t bf_status;

	// Reset key before use
    bf_rt_table_key_reset(forward_table, &forward_table_info->key);

//    // Reset data before use
//    bf_rt_table_action_data_reset(forward_table,
//                                  forward_table_info->aid_ai_unicast,
//                                  &forward_table_info->data);
//    // Reset data before use
//    bf_rt_table_action_data_reset(forward_table,
//                                  forward_table_info->aid_ai_broadcast,
//                                  &forward_table_info->data);
//	printf("DEBUG: forward_entry->action: %s in forward_polling_table_entry_add\n",
//			forward_entry->action);
//	printf("DEBUG: Add foward_polling_table_entry: TP_type: %u, ingress_port: %u,"
//			" vf_dst_ip: %x, action: %s, to port %u, mc grp id: %u\n",
//			forward_entry->polling_TP_type, forward_entry->ingress_port,
//			forward_entry->polling_vf_dst_ip, forward_entry->action,
//            forward_entry->egress_port, forward_entry->mc_grp_id);

    if (forward_entry->polling_TP_type == POLLING_FLW_TRC ||
		forward_entry->polling_TP_type == POLLING_ALL_TRC ) {
//	    printf("DEBUG: forward_polling_table_entry_add for PLOOING_FLW_TRC\n");
		// Reset key before use
	    //printf("DEBUG: bf_rt_table_key_reset in forward_polling_table_entry_add \n");

		// Fill in the Key object
		bf_status = bf_rt_key_field_set_value(forward_table_info->key,
											  forward_table_info->kid_TP_type,
											  forward_entry->polling_TP_type); 
	    assert(bf_status == BF_SUCCESS);
	
	    //printf("DEBUG: bf_rt_key_field_set_value TP type in forward_polling_table_entry_add \n");
		
		bf_status = bf_rt_key_field_set_value(forward_table_info->key,
											  forward_table_info->kid_ingress_port,
											  forward_entry->ingress_port); 
//		bf_status = bf_rt_key_field_set_value_and_mask(forward_table_info->key,
//											  forward_table_info->kid_ingress_port,
//											  forward_entry->ingress_port, 0x1ff); 
	    assert(bf_status == BF_SUCCESS);
		
		bf_status = bf_rt_key_field_set_value_and_mask(forward_table_info->key,
											  forward_table_info->kid_vf_dst_ip,
											  forward_entry->polling_vf_dst_ip, 0xffffffff); 
	    assert(bf_status == BF_SUCCESS);

	    //printf("DEBUG: bf_rt_key_field_set_value_and_mask in forward_polling_table_entry_add \n");

	    //printf("DEBUG: bf_rt_table_action_data_reset in forward_polling_table_entry_add \n");
        // Fill in the Data object
        if (strcmp(forward_entry->action, "ai_unicast_polling") == 0) {
//	        printf("DEBUG:  add ai_unicast_polling\n");
            bf_rt_table_action_data_reset(forward_table,
                                          forward_table_info->aid_ai_unicast,
                                          &forward_table_info->data);

			bf_status = bf_rt_data_field_set_value(forward_table_info->data,
	                                               forward_table_info->did_unicast_port,
	                                               forward_entry->egress_port);
	        assert(bf_status == BF_SUCCESS);
		}
		else if (strcmp(forward_entry->action, "ai_broadcast_polling") == 0) {
//	        printf("DEBUG:  add ai_broadcast_polling\n");
            // Reset data before use
            bf_rt_table_action_data_reset(forward_table,
                                          forward_table_info->aid_ai_broadcast,
                                          &forward_table_info->data);

	        bf_status = bf_rt_data_field_set_value(forward_table_info->data,
	                                               forward_table_info->did_broadcast_port,
	                                               forward_entry->egress_port);
	        assert(bf_status == BF_SUCCESS);
	
	        bf_status = bf_rt_data_field_set_value(forward_table_info->data,
	                                               forward_table_info->did_mc_grp_id,
	                                               forward_entry->mc_grp_id);
	        assert(bf_status == BF_SUCCESS);
				
		}
	    //printf("DEBUG: bf_rt_data_field_set_value in forward_polling_table_entry_add \n");
    }
	else if (forward_entry->polling_TP_type == POLLING_PFC_TRC ) {
//	    printf("DEBUG: forward_polling_table_entry_add for POLLING_PFC_TRC\n");

		// Fill in the Key object
		bf_status = bf_rt_key_field_set_value(forward_table_info->key,
											  forward_table_info->kid_TP_type,
											  forward_entry->polling_TP_type); 
	    assert(bf_status == BF_SUCCESS);
	
		bf_status = bf_rt_key_field_set_value(forward_table_info->key,
											  forward_table_info->kid_ingress_port,
											  forward_entry->ingress_port); 
		
//		bf_status = bf_rt_key_field_set_value_and_mask(forward_table_info->key,
//											  forward_table_info->kid_ingress_port,
//											  forward_entry->ingress_port, 0x1ff); 
	    assert(bf_status == BF_SUCCESS);

		// not care mask	
		bf_status = bf_rt_key_field_set_value_and_mask(forward_table_info->key,
											  forward_table_info->kid_vf_dst_ip,
											  forward_entry->polling_vf_dst_ip, 0); 
	    assert(bf_status == BF_SUCCESS);

        // Fill in the Data object
        bf_status = bf_rt_data_field_set_value(forward_table_info->data,
                                               forward_table_info->did_broadcast_port,
                                               forward_entry->egress_port);
        assert(bf_status == BF_SUCCESS);

        bf_status = bf_rt_data_field_set_value(forward_table_info->data,
                                               forward_table_info->did_mc_grp_id,
                                               forward_entry->mc_grp_id);
        assert(bf_status == BF_SUCCESS);
    }

    // Call table entry add API
    bf_status = bf_rt_table_entry_add(forward_table, session, dev_tgt,
                                      forward_table_info->key,
                                      forward_table_info->data);
	//printf("DEBUG: invoking bf_rt_table_entry_add \n");
    assert(bf_status == BF_SUCCESS);
    bf_status = bf_rt_session_complete_operations(session);
    assert(bf_status == BF_SUCCESS);
}

void forward_polling_table_deploy(const bf_rt_target_t *dev_tgt,
                                 const bf_rt_info_hdl *bfrt_info,
                                 const bf_rt_session_hdl *session,
                                 const forward_polling_entry_t *forward_list,
                                 const uint8_t forward_count) {
    bf_status_t bf_status;
    const bf_rt_table_hdl *forward_table = NULL;
    forward_polling_table_info_t forward_table_info;

    // Set up the forward table
    forward_polling_table_setup(dev_tgt, bfrt_info, &forward_table,
                        &forward_table_info);
    printf("Table forward_polling is set up correctly!\n");
#if 1
    // Add forward entries
    for (unsigned int idx = 0; idx < forward_count; idx++) {
		
//	    printf("Add foward_polling_list[%u]: TP_type: %u, ingress_port: %lu,"
//				" vf_dst_ip: %s, action: %s, to port %lu, mc grp id: %u\n",
//				idx,
//				forward_list[idx].TP_type, forward_list[idx].ingress_port,
//				forward_list[idx].vf_dst_ip_addr, forward_list[idx].action,
//	            forward_list[idx].egress_port, forward_list[idx].mc_grp_id);

		if (forward_list[idx].TP_type == POLLING_FLW_TRC ||
			forward_list[idx].TP_type == POLLING_PFC_TRC ||
			forward_list[idx].TP_type == POLLING_ALL_TRC ) { 
			forward_polling_table_entry_t forward_entry =  {
				.polling_TP_type = forward_list[idx].TP_type,
				.ingress_port = forward_list[idx].ingress_port,
				.polling_vf_dst_ip = ipv4AddrToUint32(forward_list[idx].vf_dst_ip_addr),
//				.action = forward_list[idx].action,
				.egress_port = forward_list[idx].egress_port,
				.mc_grp_id = forward_list[idx].mc_grp_id
			}; 
			strncpy(forward_entry.action, forward_list[idx].action, sizeof(forward_entry.action) - 1);
			// make sure ending with 0
			forward_entry.action[sizeof(forward_entry.action) - 1] = '\0';
        	forward_polling_table_entry_add(dev_tgt, session, forward_table,
                                &forward_table_info, &forward_entry);
//	        bf_status = bf_pm_port_str_to_dev_port_get(
//	            dev_tgt->dev_id,
//	            (char *)forward_list[idx].fp_port, &forward_entry.egress_port
//	        );
		
		}
//		else if (forward_list[idx].TP_type == POLLING_ALL_TRC ) {
//		// else if (forward_list[idx].action == "ai_broadcast_polling") {
//			forward_polling_table_entry_t forward_entry =  {
//				.polling_TP_type = forward_list[idx].TP_type,
//				.ingress_port = forward_list[idx].ingress_port,
//				.polling_vf_dst_ip = ipv4AddrToUint32(forward_list[idx].vf_dst_ip_addr),
//				.action = forward_list[idx].action,
//				.egress_port = forward_list[idx].egress_port,
//				.mc_grp_id = forward_list[idx].mc_grp_id
//			}; 
//        	forward_polling_table_entry_add(dev_tgt, session, forward_table,
//                                &forward_table_info, &forward_entry);
//
//		}
//		else if (forward_list[idx].TP_type == POLLING_PFC_TRC ) {
//			forward_polling_table_entry_t forward_entry =  {
//				.polling_TP_type = forward_list[idx].TP_type,
//				.ingress_port = forward_list[idx].ingress_port,
//				.polling_vf_dst_ip = ipv4AddrToUint32(forward_list[idx].vf_dst_ip_addr),
//				.action = forward_list[idx].action,
//				.egress_port = forward_list[idx].egress_port,
//				.mc_grp_id = forward_list[idx].mc_grp_id
//			}; 
//        	forward_polling_table_entry_add(dev_tgt, session, forward_table,
//                                &forward_table_info, &forward_entry);
//		}
    }
#endif
    printf("Table forward_polling is deployed correctly!\n");

}

static void multicast_setup(const bf_rt_target_t *dev_tgt,
							const switch_port_t* port_list,
							const uint8_t port_count,
							const uint16_t mc_grp_id) {
	bf_status_t bf_status;
    bf_mc_session_hdl_t mc_session;
    bf_mc_mgrp_hdl_t mc_mgrp;
    bf_mc_node_hdl_t mc_node;
    bf_mc_port_map_t mc_port_map;
    bf_mc_lag_map_t mc_lag_map;

    bf_status = bf_mc_create_session(&mc_session);
    assert(bf_status == BF_SUCCESS);

    //bf_status = bf_mc_mgrp_create(mc_session, dev_tgt->dev_id,
    //                              SIGNAL_MC_GID, &mc_mgrp);
    bf_status = bf_mc_mgrp_create(mc_session, dev_tgt->dev_id,
                                  mc_grp_id, &mc_mgrp);
    assert(bf_status == BF_SUCCESS);

    BF_MC_PORT_MAP_INIT(mc_port_map);
    BF_MC_LAG_MAP_INIT(mc_lag_map);

//    BF_MC_PORT_MAP_SET(mc_port_map, H1_PORT);	
//    BF_MC_PORT_MAP_SET(mc_port_map, H2_PORT);
	printf("DEBUG: Multicast setup for %u ports \n", port_count);    
	for (uint8_t idx = 0; idx < port_count; idx ++){
   		bf_dev_port_t dev_port; 
		bf_status = bf_pm_port_str_to_dev_port_get(
            dev_tgt->dev_id, (char *)port_list[idx].fp_port, &dev_port
        );	     
        BF_MC_PORT_MAP_SET(mc_port_map, dev_port);
        printf(" DEBUG: set multicast for dev_port: %d\n", dev_port);
    }

    // Rid set to 0
    bf_status = bf_mc_node_create(mc_session, dev_tgt->dev_id, 0,  //rid
                                  mc_port_map, mc_lag_map, &mc_node);
    assert(bf_status == BF_SUCCESS);
	
	// Assign node to mc_grp: level1_exclusion_id is not needed here = 0
    bf_status = bf_mc_associate_node(mc_session, dev_tgt->dev_id,
                                     mc_mgrp, mc_node, false,  0);
    assert(bf_status == BF_SUCCESS);

    bf_status = bf_mc_complete_operations(mc_session);
    assert(bf_status == BF_SUCCESS);

    bf_status = bf_mc_destroy_session(mc_session);
    assert(bf_status == BF_SUCCESS);
    printf("Muticast for %u is set up correctly!\n", mc_grp_id);
}

void multicast_group_setup(const bf_rt_target_t *dev_tgt,
							const switch_port_t* port_list,
							const uint8_t port_count) {

	/*
		for port_i in port list:
			obtain port_list_i = port_list - port_i
   			bf_dev_port_t dev_port; 
			bf_status = bf_pm_port_str_to_dev_port_get(
        	    dev_tgt->dev_id, (char *)port_list[idx].fp_port, &dev_port
        	);	     
			multicast_setup(dev_tgt, port_list_i, port_count - 1, dev_port )
			 
	*/	
	for (uint8_t i = 0; i < port_count; i++) {

        switch_port_t port_list_i[port_count - 1];
        uint8_t idx = 0;
        for (uint8_t j = 0; j < port_count; j++) {
            if (j != i) {
                port_list_i[idx++] = port_list[j];
            }
        }

        bf_dev_port_t dev_port;
        int bf_status = bf_pm_port_str_to_dev_port_get(
				dev_tgt->dev_id, (char*)port_list[i].fp_port, &dev_port);
        if (bf_status != 0) {
            fprintf(stderr, "Failed to get device port for %s\n", port_list[i].fp_port);
            continue;
        }

        multicast_setup(dev_tgt, port_list_i, port_count - 1, dev_port);
        printf("Setup multicast group id %u for ingress port %s successfully\n",
			  dev_port, port_list[i].fp_port);
    }
	
	return;
}

static void mirrorSetup(const bf_rt_target_t *dev_tgt) {
	p4_pd_status_t pd_status;
	p4_pd_sess_hdl_t mirror_session;
	// p4_pd_dev_target_t pd_dev_tgt = {dev_tgt.dev_id, dev_tgt.pipe_id};
	p4_pd_dev_target_t pd_dev_tgt = {dev_tgt->dev_id, dev_tgt->pipe_id};
//	p4_pd_mirror_session_info_t mirror_session_info = {
//		.type        = PD_MIRROR_TYPE_NORM, // Not sure
//        .dir         = PD_DIR_EGRESS,
//        .id          = 2,
//        .egr_port    = CPU_PORT,
//        .egr_port_v  = true,
//        .max_pkt_len = 16384 // Refer to example in Barefoot Academy	
//	};
	p4_pd_mirror_session_info_t mirror_session_info = {
    	PD_MIRROR_TYPE_NORM, // type
    	PD_DIR_EGRESS,       // dir
    	// EGRESS_MIRROR_SID,                   // id
        UPDATE_NOTIFY_MIRROR_SID,  // SESSION ID	
        //H2_PORT,             // egr_port 
		CPU_PORT,            // egr_port = CPU
        true,                // egr_port_v
    	0,                   // egr_port_queue (specified if necessary) 
    	PD_COLOR_GREEN,      // packet_color 
    	0,                   // mcast_grp_a
    	false,               // mcast_grp_a_v
    	0,                   // mcast_grp_b 
    	false,               // mcast_grp_b_v
    	16384,               // max_pkt_len
    	0,                   // level1_mcast_hash 
    	0,                   // level2_mcast_hash
    	0,                   // mcast_l1_xid 
    	0,                   // mcast_l2_xid
    	0,                   // mcast_rid 
    	0,                   // cos 
    	false,               // c2c
    	0,                   // extract_len 
    	0,                   // timeout_usec 
    	NULL,             // int_hdr 
    	0                    // int_hdr_len
	};
	
	pd_status = p4_pd_client_init(&mirror_session);
    assert(pd_status == BF_SUCCESS);

    // p4_pd_mirror_session_create() will enable the session by default
    pd_status = p4_pd_mirror_session_create(mirror_session, pd_dev_tgt,
                                            &mirror_session_info);
    assert(pd_status == BF_SUCCESS);	
	printf("Config Egress mirrror to CPU_PORT: %d, SID: %d\n", CPU_PORT, UPDATE_NOTIFY_MIRROR_SID);
}



static void register_setup(const bf_rt_info_hdl *bfrt_info,
                           const char *reg_name,
                           const char *value_field_name,
                           const bf_rt_table_hdl **reg,
                           register_info_t *reg_info) {
    bf_status_t bf_status;
    char reg_value_field_name[64];
//    printf("Debug: register_setup %s\n", reg_name);
    // Get table object from name
    bf_status = bf_rt_table_from_name_get(bfrt_info, reg_name, reg);
//    printf("Debug: bf_rt_table_from_name_get\n");
    assert(bf_status == BF_SUCCESS);
    
    // Allocate key and data once, and use reset across different uses
    bf_status = bf_rt_table_key_allocate(*reg, &reg_info->key);
    assert(bf_status == BF_SUCCESS);
    bf_status = bf_rt_table_data_allocate(*reg, &reg_info->data);
    assert(bf_status == BF_SUCCESS);

    // Get field-ids for key field
    bf_status = bf_rt_key_field_id_get(*reg, "$REGISTER_INDEX",
                                       &reg_info->kid_register_index);
//    printf("Debug: bf_rt_key_field_id_get\n");
    assert(bf_status == BF_SUCCESS);

    // Get field-ids for data field
    strcpy(reg_value_field_name, reg_name);
    if (value_field_name == NULL) {
        strcat(reg_value_field_name, ".f1");
    }
    else {
        strcat(reg_value_field_name, ".");
        strcat(reg_value_field_name, value_field_name);
    }
    bf_status = bf_rt_data_field_id_get(*reg, reg_value_field_name,
                                        &reg_info->did_value);
    assert(bf_status == BF_SUCCESS);
}

static void register_write(const bf_rt_target_t *dev_tgt,
                           const bf_rt_session_hdl *session,
                           const bf_rt_table_hdl *reg,
                           register_info_t *reg_info,
                           register_entry_t *reg_entry) {
    bf_status_t bf_status;

    // Reset key and data before use
    bf_rt_table_key_reset(reg, &reg_info->key);
    bf_rt_table_data_reset(reg, &reg_info->data);

    // Fill in the Key and Data object
    bf_status = bf_rt_key_field_set_value(reg_info->key,
                                          reg_info->kid_register_index,
                                          reg_entry->register_index);
    assert(bf_status == BF_SUCCESS);
    bf_status = bf_rt_data_field_set_value(reg_info->data,
                                           reg_info->did_value,
                                           reg_entry->value);
    assert(bf_status == BF_SUCCESS);

    // Call table entry add API
    bf_status = bf_rt_table_entry_add(reg, session, dev_tgt,
                                      reg_info->key, reg_info->data);
    assert(bf_status == BF_SUCCESS);
    bf_status = bf_rt_session_complete_operations(session);
    assert(bf_status == BF_SUCCESS);
}

static void register_write_no_wait(const bf_rt_target_t *dev_tgt,
                                   const bf_rt_session_hdl *session,
                                   const bf_rt_table_hdl *reg,
                                   register_info_t *reg_info,
                                   register_entry_t *reg_entry) {
    bf_status_t bf_status;

    // Reset key and data before use
    bf_rt_table_key_reset(reg, &reg_info->key);
    bf_rt_table_data_reset(reg, &reg_info->data);

    // Fill in the Key and Data object
    bf_status = bf_rt_key_field_set_value(reg_info->key,
                                          reg_info->kid_register_index,
                                          reg_entry->register_index);
    assert(bf_status == BF_SUCCESS);
    bf_status = bf_rt_data_field_set_value(reg_info->data,
                                           reg_info->did_value,
                                           reg_entry->value);
    assert(bf_status == BF_SUCCESS);

    // Call table entry add API
    bf_status = bf_rt_table_entry_add(reg, session, dev_tgt,
                                      reg_info->key, reg_info->data);
    assert(bf_status == BF_SUCCESS);
    // bf_status = bf_rt_session_complete_operations(session);
    // assert(bf_status == BF_SUCCESS);
}

static void register_read(const bf_rt_target_t *dev_tgt,
                          const bf_rt_session_hdl *session,
                          const bf_rt_table_hdl *reg,
                          register_info_t *reg_info,
                          register_entry_t *reg_entry) {
    bf_status_t bf_status;

    // Reset key and data before use
    bf_rt_table_key_reset(reg, &reg_info->key);
    bf_rt_table_data_reset(reg, &reg_info->data);

    // Fill in the Key object
    bf_status = bf_rt_key_field_set_value(reg_info->key,
                                          reg_info->kid_register_index,
                                          reg_entry->register_index);
    assert(bf_status == BF_SUCCESS);
    bf_status = bf_rt_data_field_set_value(reg_info->data,
                                           reg_info->did_value,
                                           reg_entry->value);
    assert(bf_status == BF_SUCCESS);

    // Call table entry add API
    bf_status = bf_rt_table_entry_get(reg, session, dev_tgt, reg_info->key,
                                      reg_info->data, ENTRY_READ_FROM_HW);
    assert(bf_status == BF_SUCCESS);
    bf_status = bf_rt_session_complete_operations(session);
    assert(bf_status == BF_SUCCESS);

    // Get the real values in the Data object
    // Notice: I don't know whether bf_rt_data_field_get_value_u64_array works
    // fine here, instead bf_rt_data_field_get_value_u64_array.
    bf_status = bf_rt_data_field_get_value_u64_array_size(
        reg_info->data, reg_info->did_value, &reg_entry->value_array_size
    );
    assert(bf_status == BF_SUCCESS);
    if (reg_entry->value_array) {
        printf("Debug: Free reg_entry->value_array\n");
        free(reg_entry->value_array);
    }
    reg_entry->value_array = (uint64_t *)malloc
                             (reg_entry->value_array_size * sizeof(uint64_t));
    bf_status = bf_rt_data_field_get_value_u64_array(reg_info->data,
                                                     reg_info->did_value,
                                                     reg_entry->value_array);
    assert(bf_status == BF_SUCCESS);
}

void clear_reg_table_syn(bf_rt_target_t *dev_tgt,
                          bf_rt_session_hdl *session,
                          bf_rt_table_hdl *reg) 
{
    // useless currently

    bf_status_t bf_status;
 
    //Clear the table in HW and SW
    bf_rt_begin_batch(session);
    bf_rt_table_clear(reg, session, dev_tgt);
    bf_rt_end_batch(session, true);  
    printf("Clearing reg table\n");
}

void sync_completion_cb(bf_rt_target_t *dev_tgt, void *cookie) {

    sync_context_t *sync_ctx = (sync_context_t *)cookie;
    if (sync_ctx == NULL) {
        fprintf(stderr, "completion_cb: sync_ctx is NULL\n");
        return;
    }
    else {
        printf("start sync_completion_cb\n");
    }
    clock_gettime(CLOCK_MONOTONIC, &sync_ctx->record_sync_time_end);

    long seconds = sync_ctx->record_sync_time_end.tv_sec - sync_ctx->record_sync_time_start.tv_sec;
    long nanoseconds = sync_ctx->record_sync_time_end.tv_nsec - sync_ctx->record_sync_time_start.tv_nsec;
    double elapsed = seconds + nanoseconds * 1e-9;

    printf("completion_cb Elapsed time: %.9f seconds.\n", elapsed);

    // add lock, notify 
    pthread_mutex_lock(&sync_ctx->mutex);
    sync_ctx->callback_completed = 1;
    pthread_cond_signal(&sync_ctx->cond);
    pthread_mutex_unlock(&sync_ctx->mutex);
    

}

void completion_cb(bf_rt_target_t *dev_tgt, void* cookie) {

    //Read from shadow now 
    // struct timespec start, end;
    
    // obtain start time
    clock_gettime(CLOCK_MONOTONIC, &record_sync_time_end);

     // calc time delta (s)
    long seconds = record_sync_time_end.tv_sec - record_sync_time_start.tv_sec;
    long nanoseconds = record_sync_time_end.tv_nsec - record_sync_time_start.tv_nsec;
    double elapsed = seconds + nanoseconds*1e-9;

    printf("completion_cb Elapsed time: %.9f seconds.\n", elapsed);   

    // printf("completion_cb called.\n");
  //user should read from shadow now
}


static void registers_sync(bf_rt_target_t *dev_tgt,
                          bf_rt_session_hdl *session,
                          bf_rt_table_hdl *reg,
                          register_info_t *reg_info) {
    bf_status_t bf_status;

    bf_rt_table_operations_mode_t mode = BFRT_REGISTER_SYNC;
    bf_rt_table_operations_hdl* tbl_ops;
    
    bf_status = bf_rt_table_operations_allocate(reg, mode, &tbl_ops);
    assert(bf_status == BF_SUCCESS);

    // Start timer now to record sync
    // start = system_clock::now();
    
    bf_rt_begin_batch(session);

        
    // register CB for sync 
    bf_status = bf_rt_operations_register_sync_set(tbl_ops, session, dev_tgt, completion_cb, NULL);
    assert(bf_status == BF_SUCCESS);
    
    
    // Call Sync now
    bf_status = bf_rt_table_operations_execute(reg, tbl_ops);
    assert(bf_status == BF_SUCCESS);
    
    bf_rt_end_batch(session, true);
    bf_status = bf_rt_session_complete_operations(session);
    assert(bf_status == BF_SUCCESS);
}

static void registers_get(bf_rt_target_t *dev_tgt,
                          bf_rt_session_hdl *session,
                          bf_rt_table_hdl *reg,
                          register_info_t *reg_info,
                          bf_rt_table_key_hdl **key_s,
                          bf_rt_table_data_hdl **data_s) {

    if (key_s == NULL || data_s == NULL) {
        fprintf(stderr, "Register_get key_s or data_s allocation failed.\n");
        return;
    }

    uint64_t key = 0;
    // uint64_t reg_value = 0;
    uint64_t register_values[4] = {0};
    uint32_t reg_value_array_size;


    bf_status_t bf_status;
    bf_rt_begin_batch(session);
    // get the register from shadow table
    bf_rt_entry_read_flag_e read_flag = ENTRY_READ_FROM_SW;
    // reset key 
    
    // Reset key and data before use
    bf_rt_table_key_reset(reg, &reg_info->key);
    bf_rt_table_data_reset(reg, &reg_info->data);

    // get first entry
    bf_status = bf_rt_table_entry_get_first(reg, session, dev_tgt, reg_info->key,
                                            reg_info->data, read_flag);


    
    // Fill in the Key object
    bf_status = bf_rt_key_field_get_value(reg_info->key,
                                          reg_info->kid_register_index,
                                          &key);
    assert(bf_status == BF_SUCCESS);
    // bf_status = bf_rt_data_field_get_value(reg_info->data,
    //                                        reg_info->did_value,
    //                                        register_values);
    // assert(bf_status == BF_SUCCESS);

    // Get the real values in the Data object
    // Notice: I don't know whether bf_rt_data_field_get_value_u64_array works
    // fine here, instead bf_rt_data_field_get_value_u64_array.
    // bf_status = bf_rt_data_field_get_value_u64_array_size(
    //     reg_info->data, reg_info->did_value, &reg_value_array_size
    // );
    // assert(bf_status == BF_SUCCESS);
    bf_status = bf_rt_data_field_get_value_u64_array(reg_info->data,
                                                     reg_info->did_value,
                                                     register_values);
    assert(bf_status == BF_SUCCESS);

    #if 0
// processing the first entry
    for(unsigned i = 0; i < 2; i ++){
        printf("index %u: reg_value: %lu\n", i, register_values[i]);
    }
    #endif 

    //
    // Get size of table
    //
    size_t entry_count = 0;
    bf_status = bf_rt_table_size_get(reg, &entry_count);
    assert(bf_status == BF_SUCCESS);

    //allocate key data pairs to hold the results of the query
    // bf_rt_table_key_hdl **key_s;
    // bf_rt_table_data_hdl **data_s;

    // key_s = malloc(entry_count * sizeof(bf_rt_table_key_hdl*));
    // data_s = malloc(entry_count * sizeof(bf_rt_table_data_hdl*));
    

    for (unsigned int i = 0; i < entry_count; ++i) {
        // allocate key
        bf_status = bf_rt_table_key_allocate(reg, &key_s[i]);
        assert(bf_status == BF_SUCCESS);
        
        // allocate data
        bf_status = bf_rt_table_data_allocate(reg, &data_s[i]);
        assert(bf_status == BF_SUCCESS);
    }

    // begin to get all entries 
    struct timespec polling_start, polling_end;
    clock_gettime(CLOCK_MONOTONIC, &polling_start);

    uint32_t num_returned = 0;
    bf_status = bf_rt_table_entry_get_next_n(reg, session, dev_tgt, reg_info->key,\
                                                key_s, data_s, entry_count, &num_returned, read_flag);

    clock_gettime(CLOCK_MONOTONIC, &polling_end);

    calc_time_usage(&polling_start, &polling_end, " Get_N");

    #if 0
    // processing the entries
    printf("Returned %u regs, entry_count %u regs \n", num_returned, entry_count);
    for (unsigned i = 0; i < num_returned; i ++) {   
        bf_status = bf_rt_data_field_get_value_u64_array_size(
            reg_info->data, reg_info->did_value, &reg_value_array_size
        );
        assert(bf_status == BF_SUCCESS);
        bf_status = bf_rt_data_field_get_value_u64_array(reg_info->data,
                                                        reg_info->did_value,
                                                        register_value);
        assert(bf_status == BF_SUCCESS);

        for(unsigned i = 0; i < reg_value_array_size; i ++){
            printf("index %u: reg_value: %lu\n", i, register_value[i]);
        }
       
    }
    #endif

    bf_status = bf_rt_session_complete_operations(session);
    assert(bf_status == BF_SUCCESS);

    bf_rt_end_batch(session, true);  
}


static void registers_get_hw(bf_rt_target_t *dev_tgt,
                          bf_rt_session_hdl *session,
                          bf_rt_table_hdl *reg,
                          register_info_t *reg_info,
                          bf_rt_table_key_hdl **key_s,
                          bf_rt_table_data_hdl **data_s) {

    if (key_s == NULL || data_s == NULL) {
        fprintf(stderr, "Register_get key_s or data_s allocation failed.\n");
        return;
    }

    uint64_t key = 0;
    // uint64_t reg_value = 0;
    uint64_t register_values[4] = {0};
    uint32_t reg_value_array_size;


    bf_status_t bf_status;
    bf_rt_begin_batch(session);
    // get the register from shadow table
    bf_rt_entry_read_flag_e read_flag = ENTRY_READ_FROM_HW;
    // reset key 
    
    // Reset key and data before use
    bf_rt_table_key_reset(reg, &reg_info->key);
    bf_rt_table_data_reset(reg, &reg_info->data);

    // get first entry
    bf_status = bf_rt_table_entry_get_first(reg, session, dev_tgt, reg_info->key,
                                            reg_info->data, read_flag);


    #if 0 // processing first entry
    // Fill in the Key object
    bf_status = bf_rt_key_field_get_value(reg_info->key,
                                          reg_info->kid_register_index,
                                          &key);
    assert(bf_status == BF_SUCCESS);
    // bf_status = bf_rt_data_field_get_value(reg_info->data,
    //                                        reg_info->did_value,
    //                                        register_values);
    // assert(bf_status == BF_SUCCESS);

    // Get the real values in the Data object
    // Notice: I don't know whether bf_rt_data_field_get_value_u64_array works
    // fine here, instead bf_rt_data_field_get_value_u64_array.
    // bf_status = bf_rt_data_field_get_value_u64_array_size(
    //     reg_info->data, reg_info->did_value, &reg_value_array_size
    // );
    // assert(bf_status == BF_SUCCESS);
    bf_status = bf_rt_data_field_get_value_u64_array(reg_info->data,
                                                     reg_info->did_value,
                                                     register_values);
    assert(bf_status == BF_SUCCESS);

    
// processing the first entry
    for(unsigned i = 0; i < 2; i ++){
        printf("index %u: reg_value: %lu\n", i, register_values[i]);
    }
    #endif 

    //
    // Get size of table
    //
    size_t entry_count = 0;
    bf_status = bf_rt_table_size_get(reg, &entry_count);
    assert(bf_status == BF_SUCCESS);

    //allocate key data pairs to hold the results of the query
    // bf_rt_table_key_hdl **key_s;
    // bf_rt_table_data_hdl **data_s;

    // key_s = malloc(entry_count * sizeof(bf_rt_table_key_hdl*));
    // data_s = malloc(entry_count * sizeof(bf_rt_table_data_hdl*));
    

    for (unsigned int i = 0; i < entry_count; ++i) {
        // allocate key
        bf_status = bf_rt_table_key_allocate(reg, &key_s[i]);
        assert(bf_status == BF_SUCCESS);
        
        // allocate data
        bf_status = bf_rt_table_data_allocate(reg, &data_s[i]);
        assert(bf_status == BF_SUCCESS);
    }

    // begin to get all entries 
    struct timespec polling_start, polling_end;
    clock_gettime(CLOCK_MONOTONIC, &polling_start);

    uint32_t num_returned = 0;

    // uint32_t real_entry_count = 4096;
    // if (entry_count>real_entry_count ) {
    //     printf("poll real_entry_count %u values\n", real_entry_count);
    // }

    bf_status = bf_rt_table_entry_get_next_n(reg, session, dev_tgt, reg_info->key,\
                                                key_s, data_s, entry_count, &num_returned, read_flag);

    clock_gettime(CLOCK_MONOTONIC, &polling_end);

    calc_time_usage(&polling_start, &polling_end, " Get_N");

    #if 0
    // processing the entries
    printf("Returned %u regs, entry_count %u regs \n", num_returned, entry_count);
    for (unsigned i = 0; i < num_returned; i ++) {   
        bf_status = bf_rt_data_field_get_value_u64_array_size(
            reg_info->data, reg_info->did_value, &reg_value_array_size
        );
        assert(bf_status == BF_SUCCESS);
        bf_status = bf_rt_data_field_get_value_u64_array(reg_info->data,
                                                        reg_info->did_value,
                                                        register_value);
        assert(bf_status == BF_SUCCESS);

        for(unsigned i = 0; i < reg_value_array_size; i ++){
            printf("index %u: reg_value: %lu\n", i, register_value[i]);
        }
       
    }
    #endif

    bf_status = bf_rt_session_complete_operations(session);
    assert(bf_status == BF_SUCCESS);

    bf_rt_end_batch(session, true);  
}

static void registers_syn_get(bf_rt_target_t *dev_tgt,
                          bf_rt_session_hdl *session,
                          bf_rt_table_hdl *reg,
                          register_info_t *reg_info,
                          bf_rt_table_key_hdl **key_s,
                          bf_rt_table_data_hdl **data_s, uint32_t entry_num) {
    bf_status_t bf_status;

    bf_rt_table_operations_mode_t mode = BFRT_REGISTER_SYNC;
    bf_rt_table_operations_hdl* tbl_ops;
    
    bf_status = bf_rt_table_operations_allocate(reg, mode, &tbl_ops);
    assert(bf_status == BF_SUCCESS);
    
    sync_context_t sync_ctx;
    pthread_mutex_init(&sync_ctx.mutex, NULL);
    pthread_cond_init(&sync_ctx.cond, NULL);
    sync_ctx.callback_completed = 0;
    

    bf_rt_begin_batch(session);

        
    // register sync_CB for sync 
    bf_status = bf_rt_operations_register_sync_set(tbl_ops, session, dev_tgt, sync_completion_cb, &sync_ctx);
    assert(bf_status == BF_SUCCESS);
    
    // record start time in the sync context
    clock_gettime(CLOCK_MONOTONIC, &sync_ctx.record_sync_time_start);

    // Call Sync now
    bf_status = bf_rt_table_operations_execute(reg, tbl_ops);
    assert(bf_status == BF_SUCCESS);
    
    bf_rt_end_batch(session, true);
    bf_status = bf_rt_session_complete_operations(session);
    assert(bf_status == BF_SUCCESS);

    // sleep(3);
   
//    wait until callback
    pthread_mutex_lock(&sync_ctx.mutex);
    while (!sync_ctx.callback_completed) {
        pthread_cond_wait(&sync_ctx.cond, &sync_ctx.mutex);
    }
    pthread_mutex_unlock(&sync_ctx.mutex);

    // release cond and mutex
    pthread_cond_destroy(&sync_ctx.cond);
    pthread_mutex_destroy(&sync_ctx.mutex);

    // while(!sync_ctx.callback_completed) {}
    

    if (key_s == NULL || data_s == NULL) {
        fprintf(stderr, "Register_get key_s or data_s allocation failed.\n");
        return;
    }

    uint64_t key = 0;
    // uint64_t reg_value = 0;
    uint64_t register_values[4] = {0};
    uint32_t reg_value_array_size;

    // get the register from shadow table
    bf_rt_entry_read_flag_e read_flag = ENTRY_READ_FROM_SW;
    // reset key 
    
    bf_rt_begin_batch(session);

    // Reset key and data before use
    bf_rt_table_key_reset(reg, &reg_info->key);
    bf_rt_table_data_reset(reg, &reg_info->data);

    // get first entry
    bf_status = bf_rt_table_entry_get_first(reg, session, dev_tgt, reg_info->key,
                                            reg_info->data, read_flag);



#if 1
    // processing the first entry
     // Fill in the Key object
    bf_status = bf_rt_key_field_get_value(reg_info->key,
                                          reg_info->kid_register_index,
                                          &key);
    assert(bf_status == BF_SUCCESS);
    // bf_status = bf_rt_data_field_get_value(reg_info->data,
    //                                        reg_info->did_value,
    //                                        register_values);
    // assert(bf_status == BF_SUCCESS);

    // Get the real values in the Data object
    // Notice: I don't know whether bf_rt_data_field_get_value_u64_array works
    // fine here, instead bf_rt_data_field_get_value_u64_array.
    // bf_status = bf_rt_data_field_get_value_u64_array_size(
    //     reg_info->data, reg_info->did_value, &reg_value_array_size
    // );
    // assert(bf_status == BF_SUCCESS);
    bf_status = bf_rt_data_field_get_value_u64_array(reg_info->data,
                                                     reg_info->did_value,
                                                     register_values);
    assert(bf_status == BF_SUCCESS);

    for(unsigned i = 0; i < 2; i ++){
        printf("index %u: reg_value: %lu\n", i, register_values[i]);
    }
#endif 

    //
    // Get size of table
    //
    size_t entry_count = 0;
    bf_status = bf_rt_table_size_get(reg, &entry_count);
    assert(bf_status == BF_SUCCESS);
    if (entry_num < entry_count) {
        entry_count = entry_num;
        printf("Entry Num to Get changed from %u to %u\n", entry_count, entry_num);
    } 
    

    //allocate key data pairs to hold the results of the query
    // bf_rt_table_key_hdl **key_s;
    // bf_rt_table_data_hdl **data_s;

    // key_s = malloc(entry_count * sizeof(bf_rt_table_key_hdl*));
    // data_s = malloc(entry_count * sizeof(bf_rt_table_data_hdl*));
    

    for (unsigned int i = 0; i < entry_count; ++i) {
        // allocate key
        bf_status = bf_rt_table_key_allocate(reg, &key_s[i]);
        assert(bf_status == BF_SUCCESS);
        
        // allocate data
        bf_status = bf_rt_table_data_allocate(reg, &data_s[i]);
        assert(bf_status == BF_SUCCESS);
    }

    // begin to get all entries 
    struct timespec polling_start, polling_end;
    clock_gettime(CLOCK_MONOTONIC, &polling_start);

    uint32_t num_returned = 0;
    bf_status = bf_rt_table_entry_get_next_n(reg, session, dev_tgt, reg_info->key,\
                                                key_s, data_s, entry_count, &num_returned, read_flag);

    clock_gettime(CLOCK_MONOTONIC, &polling_end);

    calc_time_usage(&polling_start, &polling_end, " bf_rt_table_entry_get_next_n");

#if 0
    // processing the entries
    printf("Returned %u regs, entry_count %u regs \n", num_returned, entry_count);
    for (unsigned i = 0; i < num_returned; i ++) {   
        bf_status = bf_rt_data_field_get_value_u64_array_size(
            reg_info->data, reg_info->did_value, &reg_value_array_size
        );
        assert(bf_status == BF_SUCCESS);
        bf_status = bf_rt_data_field_get_value_u64_array(reg_info->data,
                                                        reg_info->did_value,
                                                        register_value);
        assert(bf_status == BF_SUCCESS);

        for(unsigned i = 0; i < reg_value_array_size; i ++){
            printf("index %u: reg_value: %lu\n", i, register_value[i]);
        }
       
    }
#endif

    bf_status = bf_rt_session_complete_operations(session);
    assert(bf_status == BF_SUCCESS);

    bf_rt_end_batch(session, true);  

}


static void telemetry_reg_setup(const bf_rt_info_hdl *bfrt_info,
                telemetry_reg_t *telemetry_reg,  
                char* reg_name)
{
    // char reg_name[100];
    // sprintf(reg_name, "SwitchEgress.re_port_meter_win%d", win_idx);

    register_setup(bfrt_info, reg_name, 
                NULL, &telemetry_reg->reg, &telemetry_reg->reg_info);
    printf("Finished set up Register Name: %s\n", reg_name);
                        
}

static void telemetry_pkt_num_setup(const bf_rt_info_hdl *bfrt_info,
                               telemetry_pkt_num_t *telemetry_pkt_num_reg, uint32_t win_idx) {

    char reg_name[100];
    sprintf(reg_name, "SwitchEgress.re_telemetry_pkt_num_win%d", win_idx);

    register_setup(bfrt_info, reg_name, 
                NULL, &telemetry_pkt_num_reg->reg, &telemetry_pkt_num_reg->reg_info);
    printf("Finished set up Register Name: %s\n", reg_name);
}

static void telemetry_paused_num_setup(const bf_rt_info_hdl *bfrt_info,
                               			telemetry_paused_num_t *telemetry_paused_num_reg,
										uint32_t win_idx) {

    // Set up the paused num register win0-3
    char reg_name[100];
    sprintf(reg_name, "SwitchEgress.re_telemetry_paused_num_win%d", win_idx);
  
    register_setup(bfrt_info, reg_name, 
                    NULL, &telemetry_paused_num_reg->reg, &telemetry_paused_num_reg->reg_info);
    printf("Finished set up Register Name: %s\n", reg_name);
        
}



void telemetry_reg_batch_read(const bf_rt_target_t *dev_tgt,
                            bf_rt_session_hdl *session,
                            bf_rt_table_hdl *reg,
                          register_info_t *reg_info)
{
	bf_status_t bf_status;
    
       
    bf_rt_begin_batch(session);

  

#if 1
    // get the register from shadow table
    bf_rt_entry_read_flag_e read_flag = ENTRY_READ_FROM_HW;
    // reset key 
    
    // Reset key and data before use
    bf_rt_table_key_reset(reg, &reg_info->key);
    bf_rt_table_data_reset(reg, &reg_info->data);

    // get first entry
    bf_status = bf_rt_table_entry_get_first(reg, session, dev_tgt, reg_info->key,
                                            reg_info->data, read_flag);

    uint64_t key = 0;
    uint64_t reg_value = 0;
    uint64_t register_values[4] = {0};
    uint32_t reg_value_array_size;

    
    // Fill in the Key object
    bf_status = bf_rt_key_field_get_value(reg_info->key,
                                          reg_info->kid_register_index,
                                          &key);
    assert(bf_status == BF_SUCCESS);
    // bf_status = bf_rt_data_field_get_value(reg_info->data,
    //                                        reg_info->did_value,
    //                                        register_values);
    // assert(bf_status == BF_SUCCESS);

    // Get the real values in the Data object
    // Notice: I don't know whether bf_rt_data_field_get_value_u64_array works
    // fine here, instead bf_rt_data_field_get_value_u64_array.
    // bf_status = bf_rt_data_field_get_value_u64_array_size(
    //     reg_info->data, reg_info->did_value, &reg_value_array_size
    // );
    // assert(bf_status == BF_SUCCESS);
    bf_status = bf_rt_data_field_get_value_u64_array(reg_info->data,
                                                     reg_info->did_value,
                                                     register_values);
    assert(bf_status == BF_SUCCESS);

    #if 1
// processing the first entry
    for(unsigned i = 0; i < 2; i ++){
        printf("index %u: reg_value: %lu\n", i, register_values[i]);
    }
    #endif 

    //
    // Get size of table
    //
    size_t entry_count = 0;
    bf_status = bf_rt_table_size_get(reg, &entry_count);
    assert(bf_status == BF_SUCCESS);

    //allocate key data pairs to hold the results of the query
    bf_rt_table_key_hdl **key_s;
    bf_rt_table_data_hdl **data_s;

    key_s = malloc(entry_count * sizeof(bf_rt_table_key_hdl*));
    data_s = malloc(entry_count * sizeof(bf_rt_table_data_hdl*));
    
    if (key_s == NULL || data_s == NULL) {
        fprintf(stderr, "Memory allocation failed.\n");
        return;
    }

    for (unsigned int i = 0; i < entry_count; ++i) {
        // allocate key
        bf_status = bf_rt_table_key_allocate(reg, &key_s[i]);
        assert(bf_status == BF_SUCCESS);
        
        // allocate data
        bf_status = bf_rt_table_data_allocate(reg, &data_s[i]);
        assert(bf_status == BF_SUCCESS);
    }

    // begin to get all entries 
    struct timespec polling_start, polling_end;
    clock_gettime(CLOCK_MONOTONIC, &polling_start);

    uint32_t num_returned = 0;
    bf_status = bf_rt_table_entry_get_next_n(reg, session, dev_tgt, reg_info->key,\
                                                key_s, data_s, entry_count, &num_returned, read_flag);
    assert(bf_status == BF_SUCCESS);

    bf_status = bf_rt_session_complete_operations(session);
    assert(bf_status == BF_SUCCESS);

    clock_gettime(CLOCK_MONOTONIC, &polling_end);

    calc_time_usage(&polling_start, &polling_end, " Get_N");

    #if 1
    // processing the entries
    printf("Returned %u regs, entry_count %u regs \n", num_returned, entry_count);
    for (unsigned i = 0; i < num_returned; i ++) {
        if (i > 1){
            break;
        }   
        // bf_status = bf_rt_data_field_get_value_u64_array_size(
        //     reg_info->data, reg_info->did_value, &reg_value_array_size
        // );
        // assert(bf_status == BF_SUCCESS);
        bf_status = bf_rt_data_field_get_value_u64_array(reg_info->data,
                                                        reg_info->did_value,
                                                        register_values);
        assert(bf_status == BF_SUCCESS);

        for(unsigned i = 0; i < 2; i ++){
            printf("index %u: reg_value: %lu\n", i, register_values[i]);
        }
       
    }
    #endif

#endif 
    bf_rt_end_batch(session, true);  
}


void telemetry_reg_read(const bf_rt_target_t *dev_tgt,
                            const bf_rt_session_hdl *session,
                            telemetry_reg_t *telemetry_reg_ptr,
                            const uint32_t reg_idx,
                            FILE* file)
{
	bf_status_t bf_status;
    register_entry_t reg_entry;
    reg_entry.value_array = NULL;
    //memset(&reg_info, 0, sizeof(register_info_t));
    reg_entry.register_index = reg_idx;
    register_read(dev_tgt, session, telemetry_reg_ptr->reg,
				 &telemetry_reg_ptr->reg_info, &reg_entry);
//  check non-zero value
    // printf("    Debug: reading telemetry register %s", reg_name);
    // printf("        Debug: register read: reg_idx: %u, value array_size: %u\n", 
                // reg_idx,  reg_entry.value_array_size);
	if (reg_entry.value_array[1] == 0 && reg_entry.value_array[2] == 0)
	{	// zero value, not care
		return;
	}
	if (file != NULL) {
        fprintf(file, "Debug: reg_idx %u\n", reg_idx);
        fprintf(file, " Value %lx\n", reg_entry.value_array[0]);
        fprintf(file, " Value %lx\n", reg_entry.value_array[1]);
        fprintf(file, " Value %lx\n", reg_entry.value_array[2]);
    }
	else {
      //print to std  
		printf("Debug: reg_idx %u\n", reg_idx);
      	printf(" Value %lx\n", reg_entry.value_array[0]);
      	printf(" Value %lx\n", reg_entry.value_array[1]);
      	printf(" Value %lx\n", reg_entry.value_array[2]);
  	}
}


void telemetry_pkt_num_read(const bf_rt_target_t *dev_tgt,
								   const bf_rt_session_hdl *session,
								   telemetry_pkt_num_t *telemetry_pkt_num_ptr,
								   const uint32_t reg_idx,
								   FILE* file) {
//pkt_num_reg[table_idx]->reg, idx

	bf_status_t bf_status;
    register_entry_t reg_entry;
    reg_entry.value_array = NULL;
    //memset(&reg_info, 0, sizeof(register_info_t));
    reg_entry.register_index = reg_idx;
    register_read(dev_tgt, session, telemetry_pkt_num_ptr->reg,
				 &telemetry_pkt_num_ptr->reg_info, &reg_entry);
//  check non-zero value
    // printf("Debug:  Pktnum register read: value array_size: %u\n", reg_entry.value_array_size);
	if (reg_entry.value_array[1] == 0 && reg_entry.value_array[2] == 0)
	{	// zero value, not care
		return;
	}
	if (file != NULL) {
        fprintf(file, "Debug: reg_idx %u\n", reg_idx);
        fprintf(file, " Value %lx\n", reg_entry.value_array[0]);
        fprintf(file, " Value %lx\n", reg_entry.value_array[1]);
        fprintf(file, " Value %lx\n", reg_entry.value_array[2]);
    }
	else {
      //print to std  
		printf("Debug: reg_idx %u\n", reg_idx);
      	printf(" Value %lx\n", reg_entry.value_array[0]);
      	printf(" Value %lx\n", reg_entry.value_array[1]);
      	printf(" Value %lx\n", reg_entry.value_array[2]);
  	}
}	

void telemetry_paused_num_read(const bf_rt_target_t *dev_tgt,
								   const bf_rt_session_hdl *session,
								   telemetry_paused_num_t *telemetry_paused_num_ptr,
								   const uint32_t reg_idx,
								   FILE* file) {

	bf_status_t bf_status;
    register_entry_t reg_entry;
    reg_entry.value_array = NULL;
    //memset(&reg_info, 0, sizeof(register_info_t));
    reg_entry.register_index = reg_idx;
    register_read(dev_tgt, session, telemetry_paused_num_ptr->reg,
				 &telemetry_paused_num_ptr->reg_info, &reg_entry);
    // printf("Debug:  Paused num register read: value array_size: %u\n", reg_entry.value_array_size);
//  check non-zero value
	if (reg_entry.value_array[1] == 0 && reg_entry.value_array[2] == 0)
	{	// zero value, not care
		return;
	}
	if (file != NULL) {
        fprintf(file, "Debug: reg_idx %u\n", reg_idx);
        fprintf(file, " Value %lx\n", reg_entry.value_array[0]);
        fprintf(file, " Value %lx\n", reg_entry.value_array[1]);
        fprintf(file, " Value %lx\n", reg_entry.value_array[2]);
    }
	else {
      //print to std  
		printf("Debug: reg_idx %u\n", reg_idx);
      	printf(" Value %lx\n", reg_entry.value_array[0]);
      	printf(" Value %lx\n", reg_entry.value_array[1]);
      	printf(" Value %lx\n", reg_entry.value_array[2]);
  	}
//	printf("Debug:  reg_idx %u, ", reg_idx);
//    printf("Value %lx\n", reg_entry.value_array[2]);

}

static void re_lock_flag_setup(const bf_rt_info_hdl *bfrt_info,
                               re_lock_flag_t *re_lock_flag) {

    register_setup(bfrt_info, "SwitchEgress.re_lock_flag", 
                NULL, &re_lock_flag->reg, &re_lock_flag->reg_info);
    printf("Finished set up Register Name: SwitchEgress.re_lock_flag\n");
}
void re_lock_flag_read(const bf_rt_target_t *dev_tgt,
							   const bf_rt_session_hdl *session,
                               re_lock_flag_t *re_lock_flag) {

	bf_status_t bf_status;
    register_entry_t reg_entry;
    reg_entry.value_array = NULL;
    //memset(&reg_info, 0, sizeof(register_info_t));
    reg_entry.register_index = 0;
	reg_entry.value = 0; // init the value to 0 size <  bit<8> buggy if not init value
	printf("Debug: re_lock_flag at pipe: %x, reg_idx %u: \n ", dev_tgt->pipe_id, reg_entry.register_index);
	register_read(dev_tgt, session, re_lock_flag->reg,
			 &re_lock_flag->reg_info, &reg_entry);
    printf("Debug:  Register read: value array_size: %u\n", reg_entry.value_array_size);
	for (uint8_t idx = 0; idx < reg_entry.value_array_size; idx ++)
	{
		printf("   Arrary idx: %u:  Value %lu\n", idx, reg_entry.value_array[idx]);
	}
/*
    printf("Debug: re_lock_flag reg_idx %u, ", reg_entry.register_index);
    register_read(dev_tgt, session, re_lock_flag->reg,
				 &re_lock_flag->reg_info, &reg_entry);
    printf("Value %lx\n", reg_entry.value_array[2]);
  */  
}

void re_lock_flag_write_to_completion(const bf_rt_target_t *dev_tgt,
							   const bf_rt_session_hdl *session,
                               re_lock_flag_t *re_lock_flag, uint8_t value) {

    printf("Debug: start write re_lock_flag: set up reg_entry\n");
    register_entry_t reg_entry;
    reg_entry.register_index = 0;
    reg_entry.value = value;

//    if (&reg_entry.value==NULL){
//        printf("null reg_entry_value\n");
//    }
//    else {
//        printf("reg_entry value not null\n");
//    }

//    printf("new reg_entry.value: %u\n", reg_entry.value);
//    printf("Debug: write re_lock_flag reg_idx %u, ", reg_entry.register_index);
    register_write(dev_tgt, session, re_lock_flag->reg,
				 &re_lock_flag->reg_info, &reg_entry);
    printf("Register re_lock_flag is set to "
                "%u correctly!\n", reg_entry.value);
}


int create_update_polling_channel(update_polling_channel_t *channel) {
	struct ifreq cpuif_req;
	struct sockaddr_ll sock_addr;
    int sock_addrlen = sizeof(sock_addr);
	char cpuif_name[IFNAMSIZ];

    /* Get interface name */
    strcpy(cpuif_name, CPUIF_NAME);

    channel->sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETHER_TYPE_POLLING));
    /* Open RAW socket to send on */
	if (channel->sockfd == -1) {
	    perror("socket");
        return -1;
	}

    memset(&cpuif_req, 0, sizeof(struct ifreq));
    strncpy(cpuif_req.ifr_name, cpuif_name, IFNAMSIZ - 1);
    ioctl(channel->sockfd, SIOCGIFFLAGS, &cpuif_req);
    cpuif_req.ifr_flags |= IFF_PROMISC;
    ioctl(channel->sockfd, SIOCSIFFLAGS, &cpuif_req);

	if (setsockopt(channel->sockfd, SOL_SOCKET, SO_BINDTODEVICE,
                   cpuif_name, IFNAMSIZ - 1) == -1)	{
		perror("SO_BINDTODEVICE");
		close(channel->sockfd);
        return -1;
	}

	/* Construct the Ethernet header */
	memset(channel->recvbuf, 0, PKTBUF_SIZE);

    return 0;

}


/* Function to print polling_h details */

void parse_ports(uint16_t raw, uint16_t *port, uint8_t *padding) {
    *port = (raw >> 7) & 0x1FF;  // first 9 bit
    *padding = raw & 0x7F;       // latter 7bit
}

void print_polling_h(const polling_h *poll_h) {
    uint16_t ingress_port, egress_port;
    uint8_t padding_1, padding_2;

    // parse ports
    parse_ports((poll_h->bytes_ingress[0] << 8) | poll_h->bytes_ingress[1], &ingress_port, &padding_1);
    parse_ports((poll_h->bytes_egress[0] << 8) | poll_h->bytes_egress[1], &egress_port, &padding_2);

    printf("Polling Header Details:\n");
    printf("TP_type: %u\n", (poll_h->TP_type_w_padding_0) >> 6);
    printf("Ingress Port: %u\n", ingress_port);
    printf("Egress Port: %u\n", egress_port);
    printf("Event ID: %u\n", poll_h->event_id);
    printf("VF Source IP: %u.%u.%u.%u\n",
           (ntohl(poll_h->vf_src_ip) >> 24) & 0xFF,
           (ntohl(poll_h->vf_src_ip) >> 16) & 0xFF,
           (ntohl(poll_h->vf_src_ip) >> 8) & 0xFF,
           ntohl(poll_h->vf_src_ip) & 0xFF);
    printf("VF Destination IP: %u.%u.%u.%u\n",
           (ntohl(poll_h->vf_dst_ip) >> 24) & 0xFF,
           (ntohl(poll_h->vf_dst_ip) >> 16) & 0xFF,
           (ntohl(poll_h->vf_dst_ip) >> 8) & 0xFF,
           ntohl(poll_h->vf_dst_ip) & 0xFF);
	printf("VF Protocol: %u\n", poll_h->vf_protocol);
	printf("VF Source Port: %u\n", ntohs(poll_h->vf_src_port));
    printf("VF Destination Port: %u\n", ntohs(poll_h->vf_dst_port));
}


int recv_update_polling(update_polling_channel_t *channel){
	
	int rx_len = 0;

    /* Header structures */
    rx_len = recvfrom(channel->sockfd, channel->recvbuf,
                      PKTBUF_SIZE, 0, NULL, NULL);
    if (rx_len < 0) {
        printf("Recv failed\n");
        return -1;
    }

	struct ethhdr *eth_h = (struct ethhdr *)channel->recvbuf;

    if (ntohs(eth_h->h_proto) != ETHER_TYPE_POLLING) {  // check polling header
        printf("Not a poll packet, dropping...\n");
        return 0;
    } 

	channel->polling = (polling_h *)((char *)eth_h + sizeof(struct ethhdr));
	 // Output raw packet bytes
    printf("Received packet bytes:\n");
    for (int i = 0; i < rx_len; ++i) {
        printf("%02x ", (unsigned char)channel->recvbuf[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
    }
    printf("\n");
	
	//polling_h *poll_h = (polling_h *)((char *)eth_h + sizeof(struct ethhdr));
	print_polling_h(channel->polling);
	//print_polling_h(poll_h);	
    printf("\n");
    
	return 0;	

}



// typedef struct {
//     bf_rt_target_t *dev_tgt;
//     bf_rt_session_hdl *session;
//     bf_rt_table_hdl *reg;
//     register_info_t *reg_info;
//     bf_rt_table_key_hdl **key_s;
//     bf_rt_table_data_hdl **data_s;
// } thread_data_t;

// void *thread_func(void *arg) {
//     thread_data_t *data = (thread_data_t *)arg;
//     registers_get(data->dev_tgt, data->session, data->reg, data->reg_info, data->key_s, data->data_s);
//     return NULL;
// }
void allocate_telemetry_resources(telemetry_reg_t **reg_arr, bf_rt_table_key_hdl ****key_arr, bf_rt_table_data_hdl ****data_arr, uint32_t epoch_num, uint32_t data_size) {
    
    uint32_t e_num = epoch_num;
    uint32_t d_size = data_size;
    if (epoch_num == 0) {
        e_num = 4;
    }
    if (data_size == 0) {
        d_size = 4096;
    }

/** 
 *  re_port_meter_reg_arr =  (telemetry_reg_t *)malloc(4 * sizeof(telemetry_reg_t));
    re_port_meter_reg_key_s = malloc(4 * sizeof(bf_rt_table_key_hdl**));
    re_port_meter_reg_data_s = malloc(4 * sizeof(bf_rt_table_data_hdl**));

    for (int i = 0; i < 4; i ++){
        re_port_meter_reg_key_s[i] = malloc(4096 * sizeof(bf_rt_table_key_hdl*));
        re_port_meter_reg_data_s[i] = malloc(4096 * sizeof(bf_rt_table_data_hdl*));
    }
 */

    *reg_arr = (telemetry_reg_t *)malloc(e_num * sizeof(telemetry_reg_t));
    *key_arr = (bf_rt_table_key_hdl ***)malloc(e_num * sizeof(bf_rt_table_key_hdl **));
    *data_arr = (bf_rt_table_data_hdl ***)malloc(e_num * sizeof(bf_rt_table_data_hdl **));

    for (int i = 0; i < e_num; i++) {
        (*key_arr)[i] = malloc(d_size * sizeof(bf_rt_table_key_hdl *));
        (*data_arr)[i] = malloc(d_size * sizeof(bf_rt_table_data_hdl *));
    }
}


int main(void) {
    bf_status_t bf_status;

	int imap_status = 0;
    switch_t iswitch;

	bf_switchd_context_t *switchd_ctx;
    bf_rt_target_t *dev_tgt = &iswitch.dev_tgt;
    const bf_rt_info_hdl *bfrt_info = NULL;
    bf_rt_session_hdl **session = &iswitch.session;

    dev_tgt->dev_id = 0;
    dev_tgt->pipe_id = BF_DEV_PIPE_ALL;
	
	// Initialize and set the bf_switchd
    switchd_ctx = (bf_switchd_context_t *)
                  calloc(1, sizeof(bf_switchd_context_t));
    if (switchd_ctx == NULL) {
        printf("Cannot allocate switchd context\n");
        return -1;
    }	

    switchd_setup(switchd_ctx, P4_PROG_NAME);
    printf("\nbf_switchd is initialized successfully!\n");



    // Get BfRtInfo and create the bf_runtime session
    bfrt_setup(dev_tgt, &bfrt_info, P4_PROG_NAME, session);
    printf("bfrtInfo is got and session is created successfully!\n");

	// Set up the portable using C bf_pm api, instead of BF_RT CPP
	port_setup(dev_tgt, PORT_LIST, ARRLEN(PORT_LIST));	
    printf("$PORT table is set up successfully!\n");

    // Set up multicast to all ports (currently 4 5 6 7)
#if __TOFINO_MODE__ == 0
	multicast_group_setup(dev_tgt, PORT_LIST_A, ARRLEN(PORT_LIST_A));
	multicast_group_setup(dev_tgt, PORT_LIST_B, ARRLEN(PORT_LIST_B));
	printf("Multicast GROUP Setup finished\n");
	losslessTrafficSetUp(dev_tgt, PORT_LIST, ARRLEN(PORT_LIST));
	printf("Set up the lossless traffic \n");
	
	forward_polling_table_deploy(dev_tgt, bfrt_info, *session,
									FORWARD_POLLING_LIST, ARRLEN(FORWARD_POLLING_LIST));	
	printf("Successfully deploy forward polling table at ingress\n");
#else
	multicast_setup(dev_tgt, PORT_LIST, ARRLEN(PORT_LIST), SIGNAL_MC_GID);
	printf("Multicast Setup finished\n");
	forward_polling_table_deploy(dev_tgt, bfrt_info, *session,
								FORWARD_POLLING_LIST, ARRLEN(FORWARD_POLLING_LIST));	
	printf("Successfully deploy forward polling table at ingress\n");
#endif

	//Setup Mirror 
	mirrorSetup(dev_tgt);
	printf("Mirror Setup finished\n");
	

    
	// Setup and install entries for 2d forwarding (C-style)
	forward_2d_table_deploy(dev_tgt, bfrt_info, *session,
                         FORWARD_LIST, ARRLEN(FORWARD_LIST));
   
    // pthread_t threads[4];
    // thread_data_t thread_data[4];
    uint32_t epoch_num = 2;
    // uint32_t data_size = 4096;
    uint32_t max_entry_count = 4096; // or 65536

    re_lock_flag_t re_lock_flag; 

    
    telemetry_reg_t* re_port_meter_reg_arr;
    bf_rt_table_key_hdl*** re_port_meter_reg_key_s;
    bf_rt_table_data_hdl*** re_port_meter_reg_data_s;

    telemetry_reg_t* re_port_paused_num_reg_arr;
    bf_rt_table_key_hdl*** re_port_paused_num_reg_key_s;
    bf_rt_table_data_hdl*** re_port_paused_num_reg_data_s;

    telemetry_reg_t* re_port_enq_depth_reg_arr;
    bf_rt_table_key_hdl*** re_port_enq_depth_reg_key_s;
    bf_rt_table_data_hdl*** re_port_enq_depth_reg_data_s;

    telemetry_reg_t* re_telemetry_pkt_num_reg_arr;
    bf_rt_table_key_hdl*** re_telemetry_pkt_num_reg_key_s;
    bf_rt_table_data_hdl*** re_telemetry_pkt_num_reg_data_s;

    telemetry_reg_t* re_telemetry_enq_qdepth_reg_arr;
    bf_rt_table_key_hdl*** re_telemetry_enq_qdepth_reg_key_s;
    bf_rt_table_data_hdl*** re_telemetry_enq_qdepth_reg_data_s;

    telemetry_reg_t* re_telemetry_paused_num_reg_arr;
    bf_rt_table_key_hdl*** re_telemetry_paused_num_reg_key_s;
    bf_rt_table_data_hdl*** re_telemetry_paused_num_reg_data_s;

    telemetry_reg_t* re_telemetry_dst_ip_reg_arr;
    bf_rt_table_key_hdl*** re_telemetry_dst_ip_reg_key_s;
    bf_rt_table_data_hdl*** re_telemetry_dst_ip_reg_data_s;

    telemetry_reg_t* re_telemetry_src_ip_reg_arr;
    bf_rt_table_key_hdl*** re_telemetry_src_ip_reg_key_s;
    bf_rt_table_data_hdl*** re_telemetry_src_ip_reg_data_s;

    telemetry_reg_t* re_telemetry_src_port_reg_arr;
    bf_rt_table_key_hdl*** re_telemetry_src_port_reg_key_s;
    bf_rt_table_data_hdl*** re_telemetry_src_port_reg_data_s;

    // re_port_meter_reg_arr =  (telemetry_reg_t *)malloc(4 * sizeof(telemetry_reg_t));
    // re_port_meter_reg_key_s = malloc(4 * sizeof(bf_rt_table_key_hdl**));
    // re_port_meter_reg_data_s = malloc(4 * sizeof(bf_rt_table_data_hdl**));

    // for (int i = 0; i < 4; i ++){
    //     re_port_meter_reg_key_s[i] = malloc(4096 * sizeof(bf_rt_table_key_hdl*));
    //     re_port_meter_reg_data_s[i] = malloc(4096 * sizeof(bf_rt_table_data_hdl*));
    // }

    // wrap into this func
    allocate_telemetry_resources(&re_port_meter_reg_arr, &re_port_meter_reg_key_s, &re_port_meter_reg_data_s, epoch_num, 4096);
    allocate_telemetry_resources(&re_port_paused_num_reg_arr, &re_port_paused_num_reg_key_s, &re_port_paused_num_reg_data_s, epoch_num, 512);
    allocate_telemetry_resources(&re_port_enq_depth_reg_arr, &re_port_enq_depth_reg_key_s, &re_port_enq_depth_reg_data_s, epoch_num, 512);
    
    allocate_telemetry_resources(&re_telemetry_pkt_num_reg_arr, &re_telemetry_pkt_num_reg_key_s, &re_telemetry_pkt_num_reg_data_s, epoch_num, max_entry_count);
    allocate_telemetry_resources(&re_telemetry_enq_qdepth_reg_arr, &re_telemetry_enq_qdepth_reg_key_s, &re_telemetry_enq_qdepth_reg_data_s, epoch_num, max_entry_count);
    allocate_telemetry_resources(&re_telemetry_paused_num_reg_arr, &re_telemetry_paused_num_reg_key_s, &re_telemetry_paused_num_reg_data_s, epoch_num, max_entry_count);

    allocate_telemetry_resources(&re_telemetry_dst_ip_reg_arr, &re_telemetry_dst_ip_reg_key_s, &re_telemetry_dst_ip_reg_data_s, 1, max_entry_count);
    allocate_telemetry_resources(&re_telemetry_src_ip_reg_arr, &re_telemetry_src_ip_reg_key_s, &re_telemetry_src_ip_reg_data_s, 1, max_entry_count);
    allocate_telemetry_resources(&re_telemetry_src_port_reg_arr, &re_telemetry_src_port_reg_key_s, &re_telemetry_src_port_reg_data_s, 1, max_entry_count);


    char reg_name[128];
    for (uint32_t i = 0; i < epoch_num; i ++ ){
        snprintf(reg_name, sizeof(reg_name), "SwitchEgress.re_port_meter_win%d", i);
        telemetry_reg_setup(bfrt_info,  &(re_port_meter_reg_arr[i]), reg_name);
    }

    for (uint32_t i = 0; i < epoch_num; i ++ ){
        snprintf(reg_name, sizeof(reg_name), "SwitchEgress.re_port_paused_num_win%d", i);
        telemetry_reg_setup(bfrt_info,  &(re_port_paused_num_reg_arr[i]), reg_name);
    }
    for (uint32_t i = 0; i < epoch_num; i ++ ){
        snprintf(reg_name, sizeof(reg_name), "SwitchEgress.re_port_enq_depth_win%d", i);
        telemetry_reg_setup(bfrt_info,  &(re_port_enq_depth_reg_arr[i]), reg_name);
    }

    for (uint32_t i = 0; i < epoch_num; i ++ ){
        snprintf(reg_name, sizeof(reg_name), "SwitchEgress.re_telemetry_pkt_num_win%d", i);
        telemetry_reg_setup(bfrt_info,  &(re_telemetry_pkt_num_reg_arr[i]), reg_name);
    }
    for (uint32_t i = 0; i < epoch_num; i ++ ){
        snprintf(reg_name, sizeof(reg_name), "SwitchEgress.re_telemetry_enq_qdepth_win%d", i);
        telemetry_reg_setup(bfrt_info,  &(re_telemetry_enq_qdepth_reg_arr[i]), reg_name);
    }
    for (uint32_t i = 0; i < epoch_num; i ++ ){
        snprintf(reg_name, sizeof(reg_name), "SwitchEgress.re_telemetry_paused_num_win%d", i);
        telemetry_reg_setup(bfrt_info,  &(re_telemetry_paused_num_reg_arr[i]), reg_name);
    }


    
    snprintf(reg_name, sizeof(reg_name), "SwitchEgress.re_telemetry_dst_ip");
    telemetry_reg_setup(bfrt_info,  &(re_telemetry_dst_ip_reg_arr[0]), reg_name);

    snprintf(reg_name, sizeof(reg_name), "SwitchEgress.re_telemetry_src_ip");
    telemetry_reg_setup(bfrt_info,  &(re_telemetry_src_ip_reg_arr[0]), reg_name);
    
    snprintf(reg_name, sizeof(reg_name), "SwitchEgress.re_telemetry_src_port");
    telemetry_reg_setup(bfrt_info,  &(re_telemetry_src_port_reg_arr[0]), reg_name);  
    


    re_lock_flag_setup(bfrt_info, &re_lock_flag);
	
	// set up CPU-Dataplane channel 
	update_polling_channel_t channel;
	int status;
	status = create_update_polling_channel(&channel);	
	if(status == 0) {
		printf("polling channel created\n");
	}


    struct timespec start, end;
    
   

    // recv polling pkt and start polling 

	while(1) {
       
		// Receive packet 
        status = recv_update_polling(&channel);
		if (status == 0) {
            printf("Debug: Recv polling\n");
        }
        else {
            printf("Debug: Polling not received\n");
        }
        int res = process_event_id(channel.polling->event_id);
	    if (res == 0) {
            // poll the register
            printf("-----Start to poll all regs with epoch_num %u, max entry_count %u each FROM SW----\n", \
                epoch_num, max_entry_count);
            clock_gettime(CLOCK_MONOTONIC, &start);    


            printf("---------------Poll Port telemetry---------------\n");
            for(int i = 0; i < epoch_num; i ++){
                registers_syn_get(dev_tgt, *session, (bf_rt_table_hdl *)re_port_meter_reg_arr[i].reg,\
                            &re_port_meter_reg_arr[i].reg_info, \
                            re_port_meter_reg_key_s[i], re_port_meter_reg_data_s[i], 4096);
                            
                registers_syn_get(dev_tgt, *session, (bf_rt_table_hdl *)re_port_paused_num_reg_arr[i].reg,\
                            &re_port_paused_num_reg_arr[i].reg_info, \
                            re_port_paused_num_reg_key_s[i], re_port_paused_num_reg_data_s[i], 512);

                registers_syn_get(dev_tgt, *session, (bf_rt_table_hdl *)re_port_enq_depth_reg_arr[i].reg,\
                            &re_port_enq_depth_reg_arr[i].reg_info, \
                            re_port_enq_depth_reg_key_s[i], re_port_enq_depth_reg_data_s[i], 512);
            }

            printf("---------------Poll Flow telemetry---------------\n");
            for(int i = 0; i < epoch_num; i ++){
                registers_syn_get(dev_tgt, *session, (bf_rt_table_hdl *)re_telemetry_pkt_num_reg_arr[i].reg,\
                            &re_telemetry_pkt_num_reg_arr[i].reg_info, \
                            re_telemetry_pkt_num_reg_key_s[i], re_telemetry_pkt_num_reg_data_s[i], max_entry_count);

                registers_syn_get(dev_tgt, *session, (bf_rt_table_hdl *)re_telemetry_enq_qdepth_reg_arr[i].reg,\
                            &re_telemetry_enq_qdepth_reg_arr[i].reg_info, \
                            re_telemetry_enq_qdepth_reg_key_s[i], re_telemetry_enq_qdepth_reg_data_s[i], max_entry_count);

                registers_syn_get(dev_tgt, *session, (bf_rt_table_hdl *)re_telemetry_paused_num_reg_arr[i].reg,\
                            &re_telemetry_paused_num_reg_arr[i].reg_info, \
                            re_telemetry_paused_num_reg_key_s[i], re_telemetry_paused_num_reg_data_s[i], max_entry_count);
            }    

            printf("---------------Poll Flow 3-tuple---------------\n");
            registers_syn_get(dev_tgt, *session, (bf_rt_table_hdl *)re_telemetry_dst_ip_reg_arr[0].reg,\
                            &re_telemetry_dst_ip_reg_arr[0].reg_info, \
                            re_telemetry_dst_ip_reg_key_s[0], re_telemetry_dst_ip_reg_data_s[0], max_entry_count);

            registers_syn_get(dev_tgt, *session, (bf_rt_table_hdl *)re_telemetry_src_ip_reg_arr[0].reg,\
                            &re_telemetry_src_ip_reg_arr[0].reg_info, \
                            re_telemetry_src_ip_reg_key_s[0], re_telemetry_src_ip_reg_data_s[0], max_entry_count);

            registers_syn_get(dev_tgt, *session, (bf_rt_table_hdl *)re_telemetry_src_port_reg_arr[0].reg,\
                            &re_telemetry_src_port_reg_arr[0].reg_info, \
                            re_telemetry_src_port_reg_key_s[0], re_telemetry_src_port_reg_data_s[0], max_entry_count);
                
            clock_gettime(CLOCK_MONOTONIC, &end);    

            char print_str[256];
            snprintf(print_str, sizeof(print_str), \
                "-----Finish polling all regs with epoch_num %u, max entry_count %u each FROM SW", \
                epoch_num, max_entry_count);
            calc_time_usage(&start, &end, print_str);
                
            // reset the lock flag
            re_lock_flag_write_to_completion(dev_tgt, *session, &re_lock_flag, 0);
        	// re_lock_flag_read(dev_tgt, *session, &re_lock_flag);


	    }

    }

    return bf_status;

}
