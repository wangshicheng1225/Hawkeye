#include <core.p4>
#include <tna.p4>
#include "parsers.p4"
#include "headers.p4"
#include "../config.h"
@pa_no_overlay("egress", "eg_intr_md_for_dprsr.drop_ctl")
@pa_no_overlay("egress", "eg_intr_dprsr_md.drop_ctl")
// avoiding error that action cannot perform a range match \ 
// on key eg_md.port_meter_rate as the key does not fit \
// in under 5 PHV nibbles (i.e. 20bits) \
@pa_container_size("egress", "eg_md.port_meter_rate", 16)
@pa_container_size("egress", "eg_md.port_paused_num", 16)
// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------
parser SwitchIngressParser(
        packet_in pkt,
        out custom_header_t hdr,
        out ingress_metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;
//    StackParser() stack_parser;
	MonicaIngressStackParser() monica_ingress_parser;
    state start {
        tofino_parser.apply(pkt, ig_intr_md);
        monica_ingress_parser.apply(pkt, hdr, ig_md);
        transition accept;
    }
}


// ---------------------------------------------------------------------------
// Ingress control flow
// ---------------------------------------------------------------------------
control SwitchIngress(
        inout custom_header_t hdr,
        inout ingress_metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

    // action a_fill_ingress_tstamp() {
    //     hdr.timestamp.setValid();
    //     hdr.timestamp.ingress_mac_tstamp = ig_intr_md.ingress_mac_tstamp;
    //     hdr.timestamp.ingress_parser_tstamp = ig_intr_prsr_md.global_tstamp;
    // }
    // action ai_fill_telemetry_header() {
    //     hdr.telemetry_header.setValid();
    // }
	// set ingress CoS (iCoS = 0x04 and e_qid = 3 )
	
    action ai_nop() {
    }

	action set_icos(bit<3> icos) {
	   ig_intr_tm_md.ingress_cos =  icos; 
	}
	
	action set_queue(bit<5> qid) {
		ig_intr_tm_md.qid  = qid;
	}
	
	action set_icos_and_queue(bit<3> icos, bit<5> qid) {
	   	ig_intr_tm_md.ingress_cos =  icos; 
		ig_intr_tm_md.qid  = qid;
	}
	
	action default_set_icos_and_queue() {
	   	ig_intr_tm_md.ingress_cos = 4; 
		ig_intr_tm_md.qid  = 4;
	}
	table ti_set_traffic_class {
	    key =  {
	    // TODO: ip dscp	
		}
	
	    actions = {
			ai_nop;
	        set_icos;
	        set_queue;
	        set_icos_and_queue;
	    	default_set_icos_and_queue;
		 }
         size = 1;
         default_action = default_set_icos_and_queue;
	//    size: QUEUE_TABLE_SIZE;
	}
    // ---------- ti_forward ---------- //


    action ai_drop() {
        ig_intr_dprsr_md.drop_ctl = 1;
    }

    action ai_unicast(bit<9> port) {
        // a_fill_ingress_tstamp();
        // ai_fill_telemetry_header();
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        ig_md.bridged.ingress_port = ig_intr_md.ingress_port;
        ig_intr_tm_md.ucast_egress_port = port;
    }
 

    // @stage(3)
    action ai_unicast_polling(bit<9> port) { 
       
        hdr.polling.egress_port = port;
        ig_intr_tm_md.ucast_egress_port = port;
    }
	action ai_broadcast_polling(bit<9> port, bit<16> mc_grp_id) {
        hdr.polling.egress_port = port;// bit<9> 111111111
        ig_intr_tm_md.mcast_grp_a = mc_grp_id;

	}
    action ai_drop_polling() {
        ig_intr_dprsr_md.drop_ctl = 1;
    }
    table ti_match_polling_TP {
        key = {
            hdr.polling.TP_type: exact;
            ig_intr_md.ingress_port: exact;
            hdr.polling.vf_dst_ip: ternary;
        }
        actions = {
            ai_unicast_polling;
            ai_broadcast_polling;
            ai_drop_polling;
        }
        default_action = ai_drop_polling;
        // for debug
        // default_action = ai_unicast_polling(36); // tofino devport pipe0 
        //default_action = ai_broadcast_polling(6); // tofino mode
        //default_action = ai_unicast_polling(6); // tofino_mode
        //default_action = ai_unicast_polling(148); // tofino asic server ens8f1np1
//        default_action = ai_unicast_polling(192); // tofino asic cpu port for pipe1 
//        default_action = ai_drop;
    }
 	
    table ti_2d_forward {
 		key = {
 			ig_intr_md.ingress_port: exact;		
 			hdr.ipv4.dst_ip : exact;
 		}
         actions = {
             ai_unicast;
             ai_drop;
         }
         size = 64;
         default_action = ai_drop;
 	} 
	action ai_multicast() {

		ig_intr_tm_md.mcast_grp_a = SIGNAL_MC_GID;
        ig_md.bridged.ingress_port = ig_intr_md.ingress_port;	
	} 
	table ti_mark_multicast {
		key = {}
		actions = {
			ai_multicast;
		}
		size = 1;
		default_action = ai_multicast;
	}
 
    action ai_reflect() {
        ig_intr_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
    }
	table ti_reflect {
		key = {}
		actions = {
			ai_reflect;
		}
		size = 1;
		default_action = ai_reflect;
	}
    // Processing Logic
    apply {
		
		ti_set_traffic_class.apply();
		if (hdr.ethernet.ether_type == ETHERTYPE_PAUSE) {	
			//ti_match_polling_TP.apply();
//			reflect to egress to update pause timer			
			ti_reflect.apply();
		}
		else if (hdr.ethernet.ether_type == ETHERTYPE_POLLING) {
	       	ti_match_polling_TP.apply();	
        }

		else {	
//			ti_forward.apply();
// using 2d forward to emulate multiple logic switch in one Tofino
			ti_2d_forward.apply();
		}
	}
    
}

// -----------------------------------------------------------------------------
// Ingress deparser
// -----------------------------------------------------------------------------
control SwitchIngressDeparser(
        packet_out pkt,
        inout custom_header_t hdr,
        in ingress_metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {

    apply {
        pkt.emit(ig_md.bridged); // Only Ingress
        pkt.emit(hdr); // for now only emitting tcp
//		pkt.emit(hdr.ethernet); // custom header contains timestamp_header  
//    	pkt.emit(hdr.ipv4);
//		pkt.emit(hdr.tcp);
	}
}



// ---------------------------------------------------------------------------
// Egress parser
// ---------------------------------------------------------------------------
parser SwitchEgressParser(
        packet_in pkt,
        out custom_header_t hdr,
        out egress_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {


    TofinoEgressParser() tofino_parser;
    MonicaEgressStackParser() monica_egress_parser;
	state start {
        tofino_parser.apply(pkt, eg_intr_md);
        monica_egress_parser.apply(pkt, hdr, eg_md);
        transition accept;
    }


}




// ---------------------------------------------------------------------------
// Egress control flow
// ---------------------------------------------------------------------------
control SwitchEgress(
        inout custom_header_t hdr,
        inout egress_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_prsr_md,
        inout egress_intrinsic_metadata_for_deparser_t eg_intr_dprsr_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {

	   	 
    action ae_nop() { }
   
	// port-meter
    Hash<bit<TUPLE_IDX_SIZE>>(HashAlgorithm_t.CRC16) port_tuple_calc;
    
    action ae_port_tuple_idx_calc(){
        // calculate the inport-eport hash into 16bit flow id
        eg_md.port_tuple_idx = port_tuple_calc.get({ 
                                            eg_md.bridged.ingress_port,
                                            eg_intr_md.egress_port });
    }
    //@stage(1)
    table te_port_tuple_idx_calc {
        actions = { ae_port_tuple_idx_calc;}
        size = 1;
        const default_action = ae_port_tuple_idx_calc();
    }
/*
	action ae_mark_port_meter_rate(bit<1> flag) {
		eg_md.high_port_meter_rate = flag;
	}	
	table te_filter_port_meter {
		key = {eg_md.port_meter_rate: range;}
		actions = {
			ae_mark_port_meter_rate;
		}
		const entries = {
			0 .. 128: ae_mark_port_meter_rate(0);
			129 .. 65535: ae_mark_port_meter_rate(1);
		}
		const default_action = ae_mark_port_meter_rate(0);
	}
*/	
	Hash<bit<16>>(HashAlgorithm_t.CRC16) flow_idx_calc;
    
    action ae_flow_idx_calc(){
        // calculate the 5-tuple hash into 32bit flow id
        eg_md.flow_idx = flow_idx_calc.get({ hdr.ipv4.protocol,
                                            hdr.ipv4.dst_ip,
                                            hdr.ipv4.src_ip,
                                            hdr.tcp.dst_port,
                                            hdr.tcp.src_port });
    }
    //@stage(1)
    table te_flow_idx_calc {
        actions = { ae_flow_idx_calc;}
        size = 1;
        const default_action = ae_flow_idx_calc();
    }

  
    Register<bit<32>, _>(1,0) re_initial_tstamp;
    RegisterAction<_, _, bit<32>> (re_initial_tstamp) rae_set_reltv_tstamp = {
        void apply(inout bit<32> value, out bit<32> output) {
            if (eg_intr_prsr_md.global_tstamp[31:0] >= value) {
                output = eg_intr_prsr_md.global_tstamp[31:0] - value;
            }
            else {
                output = 0;
            }
        }
    };
	
    action ae_reltv_tstamp_extract() {
		// extract 48bit into 32bit
        eg_md.reltv_tstamp = rae_set_reltv_tstamp.execute(0);
    }

    //@stage(0)
	table te_reltv_tstamp_extract {
		key = {}
		actions = { ae_reltv_tstamp_extract; }
		size = 1;
		const default_action = ae_reltv_tstamp_extract();
	} 

    // Gen win id and select the register
    action ae_epoch_idx_gen(){
        // 
      	// eg_md.epoch_idx = eg_md.reltv_tstamp[23:22]; // 4*8ms
		// eg_md.epoch_no = eg_md.reltv_tstamp[31:24]; // 8bit

        // to reduce stage 
        eg_md.reltv_tstamp = eg_intr_prsr_md.global_tstamp[31:0];
        eg_md.epoch_idx = eg_intr_prsr_md.global_tstamp[23:22]; // 4*8ms

    }

    //@stage(1)
    table te_epoch_idx_gen {
        key = {}
		actions = { ae_epoch_idx_gen; }
        size = 1;
        const default_action = ae_epoch_idx_gen();
    }

// 
	Register<bit<8>, _>(1) re_last_epoch_idx;
	RegisterAction<_, _, bit<FLAG_WIDTH>>(re_last_epoch_idx) rae_update_epoch_idx = {
		void apply(inout bit<8> value, out bit<FLAG_WIDTH> output) {
			output = 0;
			if (eg_md.epoch_idx != value[1:0] ) {
				output = 1;
				value = (bit<8>)eg_md.epoch_idx;
			}
		}	
	};
	action ae_update_change_epoch(){
		eg_md.change_epoch = rae_update_epoch_idx.execute(0); 
	}
	table te_update_change_epoch {
		key = {}	
		actions = {ae_update_change_epoch; ae_nop;}
		default_action = ae_update_change_epoch();	
	}

	Register<bit<TSTAMP_US_WIDTH>,_> (512,0) re_pkt_last_timer; // us
	Register<bit<TSTAMP_US_WIDTH>,_> (512,0) re_pause_timer; // us
	
	RegisterAction<_,_,bit<TSTAMP_US_WIDTH>>(re_pkt_last_timer) rae_update_pkt_last_timer = {
		void apply(inout bit<TSTAMP_US_WIDTH> value, out bit<TSTAMP_US_WIDTH> output) {
//			output = (bit<32>) eg_intr_prsr_md.global_tstamp[32:0] - value;
//			value = (bit<32>)eg_intr_prsr_md.global_tstamp[32:0]; 
			output= eg_md.reltv_tstamp[25:10] - value;
			value = eg_md.reltv_tstamp[25:10];
		}
	};
	action ae_update_pkt_last_timer() {
		eg_md.time_delta = rae_update_pkt_last_timer.execute(eg_intr_md.egress_port);
	}

	RegisterAction<_, _, bit<TSTAMP_US_WIDTH>>(re_pkt_last_timer) rae_set_pkt_last_timer = {
		void apply(inout bit<TSTAMP_US_WIDTH> value, out bit<TSTAMP_US_WIDTH> output) {
//			output = eg_intr_prsr_md.global_tstamp[32:0];
//			value = eg_intr_prsr_md.global_tstamp[32:0]; 
			output = eg_md.reltv_tstamp[25:10];
			value = eg_md.reltv_tstamp[25:10];
		}
	};
	action ae_set_pkt_last_timer() {
		// no need to the return value
		eg_md.time_delta = rae_set_pkt_last_timer.execute(eg_intr_md.egress_port);
	}
   table te_select_update_pkt_last_timer {
        key = {
            hdr.ethernet.ether_type: exact;
        }
        actions = {
            ae_nop;
            ae_set_pkt_last_timer;
            ae_update_pkt_last_timer;
        }
        const entries = {														
			(ETHERTYPE_PAUSE) : ae_set_pkt_last_timer;
            (ETHERTYPE_IPV4) : ae_update_pkt_last_timer;
		}	
        const default_action = ae_nop;
    }

	RegisterAction<_, _, bit<FLAG_WIDTH>>(re_pause_timer) rae_update_pause_timer = {
		void apply(inout bit<TSTAMP_US_WIDTH> value, out bit<FLAG_WIDTH> is_paused) {
			is_paused  = 0;
			if (value > eg_md.time_delta) {
				// paused_remaining time > time_delta
				is_paused = 1;
				value = value - eg_md.time_delta;	
			}
			else
			{
				is_paused  = 0;
				value = 0;	
			}
		}
	};
	action ae_update_pause_timer() {
		eg_md.is_paused = rae_update_pause_timer.execute(eg_intr_md.egress_port);
	}

	RegisterAction<_, _, bit<FLAG_WIDTH>>(re_pause_timer) rae_set_pause_timer = {
		void apply(inout bit<TSTAMP_US_WIDTH> value, out bit<FLAG_WIDTH> is_paused) {
			is_paused  = 1;
			value = 0x347; // set static 0xffff * 512 /40G ~= 839 us	
			//value = (bit<32>)(hdr.pause.pause_time * 13); // *512/40e9 ~= 12.8 (ns)
//			value = (bit<32>)(hdr.pause.pause_time) << 4; // *512/40e9 ~= 12.8 (ns)
		}
	};
	action ae_set_pause_timer_drop() {
		eg_md.is_paused = rae_set_pause_timer.execute(eg_intr_md.egress_port);
        eg_intr_dprsr_md.drop_ctl = 1;// drop for pause frame
	}
    
    table te_select_update_pause_timer {
        key = {
            hdr.ethernet.ether_type: exact;
        }
        actions = {
            ae_nop;
//            ae_set_pause_timer;
            ae_set_pause_timer_drop;
            ae_update_pause_timer;
        }
        const entries = {														
			(ETHERTYPE_PAUSE) : ae_set_pause_timer_drop;
            (ETHERTYPE_IPV4) : ae_update_pause_timer;
		}	
        const default_action = ae_nop(); 
    }




// update enq_qdepth num
    Register<bit<16>, _>(65536) re_telemetry_enq_qdepth_win0;
    Register<bit<16>, _>(65536) re_telemetry_enq_qdepth_win1;
    Register<bit<16>, _>(65536) re_telemetry_enq_qdepth_win2;
    Register<bit<16>, _>(65536) re_telemetry_enq_qdepth_win3;
    

#define UPDATE_TELEMETRY_ENQ_QDEPTH(EP_IDX)									    \
	RegisterAction<_, _, bit<16>>(re_telemetry_enq_qdepth_win##EP_IDX##)	    \
								 rae_telemetry_enq_qdepth_win##EP_IDX## = {	    \
        void apply(inout bit<16> value, out bit<16> output) {				    \
			output = 0;														    \
			if (eg_md.should_reset_flow_epoch_data == 1) {					    \
				value = eg_intr_md.enq_qdepth[15:0];						    \
			}																    \
			else {															    \
				bit<16> in_v;												    \
				in_v = value;												    \
				value = value + eg_intr_md.enq_qdepth[15:0];				    \
				output = in_v;												    \
			}																    \
        }																	    \
    };																		    \
    action ae_update_re_telemetry_enq_qdepth_win##EP_IDX##() {				    \
        eg_md.enq_qdepth = 													    \
			rae_telemetry_enq_qdepth_win##EP_IDX##.execute(eg_md.flow_idx);	    \
	}																		    \
    action ae_ufqn_win##EP_IDX##() {}                                           \
    table te_update_re_telemetry_unpaused_enq_qdepth_win##EP_IDX## {			\
        key = {                                                                 \
            eg_md.epoch_idx: exact;                                             \
            eg_md.lock_flag: exact;                                             \
            eg_md.is_paused: exact;                                             \
        }										                                \
        actions = { ae_update_re_telemetry_enq_qdepth_win##EP_IDX##;		    \
					 ae_ufqn_win##EP_IDX##; }								    \
		const entries = {													    \
            (##EP_IDX##, 0,0): ae_update_re_telemetry_enq_qdepth_win##EP_IDX##();\
		}																	    \
        const default_action = ae_ufqn_win##EP_IDX##();						    \
    }																		    \

	UPDATE_TELEMETRY_ENQ_QDEPTH(0)	
	UPDATE_TELEMETRY_ENQ_QDEPTH(1)
	UPDATE_TELEMETRY_ENQ_QDEPTH(2)
	UPDATE_TELEMETRY_ENQ_QDEPTH(3)

    // update pkt num
    Register<bit<16>, _>(65536, 0) re_telemetry_pkt_num_win0;
    Register<bit<16>, _>(65536, 0) re_telemetry_pkt_num_win1;
    Register<bit<16>, _>(65536, 0) re_telemetry_pkt_num_win2;
    Register<bit<16>, _>(65536, 0) re_telemetry_pkt_num_win3;
    
#define UPDATE_TELEMETRY_PKT_NUM(EP_IDX)									        \
	RegisterAction<_, _, bit<16>>(re_telemetry_pkt_num_win##EP_IDX##)		        \
								 rae_telemetry_pkt_num_win##EP_IDX## = {	        \
        void apply(inout bit<16> value, out bit<16> output) {				        \
			output = 0;														        \
			if (eg_md.should_reset_flow_epoch_data == 1) {					        \
				value = 1;													        \
			}																        \
			else {															        \
				bit<16> in_v;												        \
				in_v = value;												        \
				value = value + 1;											        \
				output = in_v;												        \
			}																        \
        }																	        \
    };																		        \
    action ae_update_re_telemetry_pkt_num_win##EP_IDX##() {					        \
        eg_md.pkt_num = 													        \
			rae_telemetry_pkt_num_win##EP_IDX##.execute(eg_md.flow_idx);	        \
	}																		        \
    action ae_ufpn_win##EP_IDX##() {}                                               \
    table te_update_re_telemetry_pkt_num_win##EP_IDX## {					        \
        key = {                                                                     \
            eg_md.epoch_idx: exact;                                                 \
            eg_md.lock_flag: exact;                                                 \
        }									                            	        \
        actions = { ae_update_re_telemetry_pkt_num_win##EP_IDX##;			        \
					 ae_ufpn_win##EP_IDX##; }								        \
		const entries = {													        \
			(##EP_IDX##, 0) : ae_update_re_telemetry_pkt_num_win##EP_IDX##();	    \
		}																	        \
        const default_action = ae_ufpn_win##EP_IDX##();						        \
    }																		        \

	UPDATE_TELEMETRY_PKT_NUM(0)	
	UPDATE_TELEMETRY_PKT_NUM(1)	
	UPDATE_TELEMETRY_PKT_NUM(2)	
	UPDATE_TELEMETRY_PKT_NUM(3)	

    // update pfc_pause_num
    Register<bit<16>, _>(65536, 0) re_telemetry_paused_num_win0;
    Register<bit<16>, _>(65536, 0) re_telemetry_paused_num_win1;
    Register<bit<16>, _>(65536, 0) re_telemetry_paused_num_win2;
    Register<bit<16>, _>(65536, 0) re_telemetry_paused_num_win3;

#define UPDATE_TELEMETRY_PAUSED_NUM(EP_IDX)										                \
	RegisterAction<_, _, bit<16>>(re_telemetry_paused_num_win##EP_IDX##)		                \
								 rae_telemetry_paused_num_win##EP_IDX## = {		                \
        void apply(inout bit<16> value, out bit<16> output) {					                \
			output = 0;															                \
			if (eg_md.should_reset_flow_epoch_data == 1 ) {										\
				value = (bit<16>)(eg_md.is_paused);								                \
			}																	                \
			else {																                \
				bit<16> in_v;													                \
				in_v = value;													                \
				value = value + (bit<16>)(eg_md.is_paused);						                \
				output = in_v;													                \
			}																	                \
        }																		                \
    };																			                \
    action ae_update_re_telemetry_paused_num_win##EP_IDX##() {					                \
        eg_md.flow_paused_num = 														        \
			rae_telemetry_paused_num_win##EP_IDX##.execute(eg_md.flow_idx);		                \
	}																			                \
    table te_update_re_telemetry_paused_num_win##EP_IDX## {						                \
        key = {                                                                                 \
            eg_md.epoch_idx: exact;                                                             \
            eg_md.lock_flag: exact;                                                             \
        }											                                            \
        actions = { ae_update_re_telemetry_paused_num_win##EP_IDX##;			                \
					 ae_nop; }													                \
		const entries = {														                \
			(##EP_IDX##, 0) : ae_update_re_telemetry_paused_num_win##EP_IDX##();	            \
		}																		                \
        const default_action = ae_nop();										                \
    }																			                \

	UPDATE_TELEMETRY_PAUSED_NUM(0)
	UPDATE_TELEMETRY_PAUSED_NUM(1)
	UPDATE_TELEMETRY_PAUSED_NUM(2)
	UPDATE_TELEMETRY_PAUSED_NUM(3)


    Register<bit<16>, _>(65536) re_telemetry_egress_port;
    Register<bit<32>, _>(65536) re_telemetry_dst_ip;
    Register<bit<32>, _>(65536) re_telemetry_src_ip;
    Register<bit<16>, _>(65536) re_telemetry_dst_port;
    Register<bit<16>, _>(65536) re_telemetry_src_port;

	RegisterAction<_, _, bit<16>>(re_telemetry_egress_port)		                
								 rae_telemetry_egress_port = {		                
        void apply(inout bit<16> value) {					                
			value = (bit<16>)(eg_intr_md.egress_port);								                
//			output = (bit<16>)(eg_intr_md.egress_port);								                
        }																		                
    };																			                
    action ae_update_re_telemetry_egress_port() {					                
		rae_telemetry_egress_port.execute(eg_md.flow_idx);		                
	}	
    table te_update_re_telemetry_egress_port {						                
        key = {                                                                                 
            eg_md.lock_flag: exact;                                                             
        }											                                            
        actions = {
            ae_update_re_telemetry_egress_port; 
			ae_nop; }													                
		const entries = {														                
			(0) : ae_update_re_telemetry_egress_port;
		}																		                
        const default_action = ae_nop();										                
    }																			                
 
	RegisterAction<_, _, bit<32>>(re_telemetry_dst_ip)		                
								 rae_telemetry_dst_ip = {		                
        void apply(inout bit<32> value) {					                
			value = (bit<32>)(hdr.ipv4.dst_ip);								                
        }																		                
    };																			                
    action ae_update_re_telemetry_dst_ip() {					                
		rae_telemetry_dst_ip.execute(eg_md.flow_idx);		                
	}	
    table te_update_re_telemetry_dst_ip {						                
        key = {                                                                                 
            eg_md.lock_flag: exact;                                                             
        }											                                            
        actions = {
            ae_update_re_telemetry_dst_ip; 
			ae_nop; }													                
		const entries = {														                
			(0) : ae_update_re_telemetry_dst_ip;
		}																		                
        const default_action = ae_nop();										                
    }																			                
	
	RegisterAction<_, _, bit<32>>(re_telemetry_src_ip)		                
								 rae_telemetry_src_ip = {		                
        void apply(inout bit<32> value) {					                
			value = (bit<32>)(hdr.ipv4.src_ip);								                
        }																		                
    };																			                
    action ae_update_re_telemetry_src_ip() {					                
		rae_telemetry_src_ip.execute(eg_md.flow_idx);		                
	}	
    table te_update_re_telemetry_src_ip {						                
        key = {                                                                                 
            eg_md.lock_flag: exact;                                                             
        }											                                            
        actions = {
            ae_update_re_telemetry_src_ip; 
			ae_nop; }													                
		const entries = {														                
			(0) : ae_update_re_telemetry_src_ip;
		}																		                
        const default_action = ae_nop();										                
    }																			                
	
	RegisterAction<_, _, bit<16>>(re_telemetry_dst_port)		                
								 rae_telemetry_tcp_dst_port = {		                
        void apply(inout bit<16> value) {					                
			value = (hdr.tcp.dst_port);
        }																		                
    };																			                
    action ae_update_re_telemetry_tcp_dst_port() {					                
		rae_telemetry_tcp_dst_port.execute(eg_md.flow_idx);		                
	}	
	RegisterAction<_, _, bit<16>>(re_telemetry_dst_port)		                
								 rae_telemetry_udp_dst_port = {		                
        void apply(inout bit<16> value) {					                
			value = (hdr.udp.dst_port);
        }																		                
    };																			                
    action ae_update_re_telemetry_udp_dst_port() {					                
		rae_telemetry_udp_dst_port.execute(eg_md.flow_idx);		                
	}
	table te_update_re_telemetry_dst_port {
        key = {                                                                                 
            eg_md.lock_flag: exact;                                                             
        	hdr.ipv4.protocol: exact;
		}											                                            
        actions = {
			ae_update_re_telemetry_tcp_dst_port;
			ae_update_re_telemetry_udp_dst_port;
			ae_nop; }													                
		const entries = {														                
			(0, IP_PROTOCOLS_TCP) : ae_update_re_telemetry_tcp_dst_port;
			(0, IP_PROTOCOLS_UDP) : ae_update_re_telemetry_udp_dst_port;
		}																		                
        const default_action = ae_nop();										                
    }																			                

	RegisterAction<_, _, bit<16>>(re_telemetry_src_port)		                
								 rae_telemetry_tcp_src_port = {		                
        void apply(inout bit<16> value) {					                
			value = (hdr.tcp.src_port);
        }																		                
    };																			                
    action ae_update_re_telemetry_tcp_src_port() {					                
		rae_telemetry_tcp_src_port.execute(eg_md.flow_idx);		                
	}	
	RegisterAction<_, _, bit<16>>(re_telemetry_src_port)		                
								 rae_telemetry_udp_src_port = {		                
        void apply(inout bit<16> value) {					                
			value = (hdr.udp.src_port);
        }																		                
    };																			                
    action ae_update_re_telemetry_udp_src_port() {					                
		rae_telemetry_udp_src_port.execute(eg_md.flow_idx);		                
	}
	table te_update_re_telemetry_src_port {
        key = {                                                                                 
            eg_md.lock_flag: exact;                                                             
        	hdr.ipv4.protocol: exact;
		}											                                            
        actions = {
			ae_update_re_telemetry_tcp_src_port;
			ae_update_re_telemetry_udp_src_port;
			ae_nop; }													                
		const entries = {														                
			(0, IP_PROTOCOLS_TCP) : ae_update_re_telemetry_tcp_src_port;
			(0, IP_PROTOCOLS_UDP) : ae_update_re_telemetry_udp_src_port;
		}																		                
        const default_action = ae_nop();										                
    }																			                
//    table te_update_re_telemetry_tcp_dst_src_port {						                
//        key = {                                                                                 
//            eg_md.lock_flag: exact;                                                             
//        	hdr.ipv4.protocol: exact;
//		}											                                            
//        actions = {
//            ae_update_re_telemetry_tcp_dst_src_port;
//			ae_nop; }													                
//		const entries = {														                
//			(0, IP_PROTOCOLS_TCP) : ae_update_re_telemetry_tcp_dst_src_port;
//		}																		                
//        const default_action = ae_nop();										                
//    }																			                
//    table te_update_re_telemetry_udp_dst_src_port {						                
//        key = {                                                                                 
//            eg_md.lock_flag: exact;                                                             
//        	hdr.ipv4.protocol: exact;
//		}											                                            
//        actions = {
//			ae_update_re_telemetry_udp_dst_src_port; 
//			ae_nop; }													                
//		const entries = {														                
//			(0, IP_PROTOCOLS_UDP) : ae_update_re_telemetry_udp_dst_src_port;
//		}																		                
//        const default_action = ae_nop();										                
//    }																			                


	Register<bit<16>, _>(PORT_METER_SIZE, 250) re_port_meter_win0;
	Register<bit<16>, _>(PORT_METER_SIZE, 251) re_port_meter_win1;
	Register<bit<16>, _>(PORT_METER_SIZE, 252) re_port_meter_win2;
	Register<bit<16>, _>(PORT_METER_SIZE, 253) re_port_meter_win3;
//	Register<bit<16>, _>(PORT_METER_SIZE, 0) re_port_meter_sum;

#define UPDATE_PORT_METER(EP_IDX)												\
	RegisterAction<_, _, bit<16>>(re_port_meter_win##EP_IDX##)					\
						rae_update_port_meter_win##EP_IDX## = {					\
        void apply(inout bit<16> value, out bit<16> output) {					\
            output = 1; 														\
			if (eg_md.change_epoch == 1) {										\
				value =  1; 													\
			}											  						\
			else {																\
				value = value + 1;												\
			}        															\
																				\
        }																		\
    };																			\
	action ae_update_port_meter_win##EP_IDX##() {								\
        eg_md.port_meter_rate =                          						\
			rae_update_port_meter_win##EP_IDX##.execute(eg_md.port_tuple_idx);	\
	}																			\
	RegisterAction<_, _, bit<16>>(re_port_meter_win##EP_IDX##) 				    \
							rae_read_port_meter_win##EP_IDX## = {			    \
        void apply(inout bit<16> value, out bit<16> output) {				    \
			output = value;													    \
        }																	    \
	};																		    \
	action ae_read_port_meter_win##EP_IDX##() {							        \
        eg_md.port_meter_rate =                         					    \
		  rae_read_port_meter_win##EP_IDX##.execute(eg_md.port_tuple_idx);	    \
    }																		    \
    action ae_upm_nop_win##EP_IDX##() {}                                        \
    table te_update_re_port_meter_win##EP_IDX##{								\
        key = {                                                                 \
            eg_md.epoch_idx: exact;                                           \
            hdr.ethernet.ether_type: exact;                                     \
        }                                                                       \
		actions = {                                                             \
			ae_update_port_meter_win##EP_IDX##;                                 \
			ae_upm_nop_win##EP_IDX##;                                           \
            ae_read_port_meter_win##EP_IDX##;                                   \
		}                                                                       \
		const entries = {														\
			(##EP_IDX##, ETHERTYPE_IPV4): ae_update_port_meter_win##EP_IDX##();	\
            (##EP_IDX##, ETHERTYPE_POLLING): ae_read_port_meter_win##EP_IDX##();\
		}																		\
        const default_action = ae_upm_nop_win##EP_IDX##();                      \
    }                                                                           \


	UPDATE_PORT_METER(0) 
	UPDATE_PORT_METER(1) 
	UPDATE_PORT_METER(2) 
	UPDATE_PORT_METER(3) 
	
	Register<bit<16>, _>(512, 0) re_port_paused_num_win0;
	Register<bit<16>, _>(512, 0) re_port_paused_num_win1;
	Register<bit<16>, _>(512, 0) re_port_paused_num_win2;
	Register<bit<16>, _>(512, 0) re_port_paused_num_win3;
//	Register<bit<16>, _>(PORT_METER_SIZE, 0) re_port_meter_sum;

#define UPDATE_PORT_PAUSED_NUM(EP_IDX)												    \
	RegisterAction<_, _, bit<16>>(re_port_paused_num_win##EP_IDX##)					        \
						rae_update_port_paused_num_win##EP_IDX## = {					        \
        void apply(inout bit<16> value, out bit<16> output) {					        \
			output = 0;															                \
			if (eg_md.change_epoch == 1 ) {								                \
				value = (bit<16>)(eg_md.is_paused);								                \
			}																	                \
			else {																                \
				bit<16> in_v;													                \
				in_v = value;													                \
				value = value + (bit<16>)(eg_md.is_paused);						                \
				output = in_v;													                \
			}																	                \
        }																		        \
    };																			        \
	action ae_update_port_paused_num_win##EP_IDX##() {								    \
        eg_md.port_paused_num =                          						            \
			rae_update_port_paused_num_win##EP_IDX##.execute(eg_intr_md.egress_port);	\
	}																			        \
	RegisterAction<_, _, bit<16>>(re_port_paused_num_win##EP_IDX##) 				    \
							rae_read_port_paused_num_win##EP_IDX## = {			        \
        void apply(inout bit<16> value, out bit<16> output) {				            \
			output = value;													            \
        }																	            \
	};																		            \
	action ae_read_port_paused_num_win##EP_IDX##() {							                \
        eg_md.port_paused_num =   					                        \
		  rae_read_port_paused_num_win##EP_IDX##.execute(eg_intr_md.egress_port);	            \
    }																		            \
    action ae_upause_nop_win##EP_IDX##() {}                                                \
    table te_update_re_port_paused_num_win##EP_IDX##{								        \
        key = {                                                                         \
            eg_md.epoch_idx: exact;                                                   \
            hdr.ethernet.ether_type: exact;                                             \
        }                                                                               \
		actions = {                                                                     \
			ae_update_port_paused_num_win##EP_IDX##;                                         \
            ae_read_port_paused_num_win##EP_IDX##;                                           \
			ae_upause_nop_win##EP_IDX##;                                                \
		}                                                                               \
		const entries = {														        \
			(##EP_IDX##, ETHERTYPE_IPV4): ae_update_port_paused_num_win##EP_IDX##();	\
            (##EP_IDX##, ETHERTYPE_POLLING): ae_read_port_paused_num_win##EP_IDX##();   \
		}																		        \
        const default_action = ae_upause_nop_win##EP_IDX##();                           \
    }                                                                                   \

    UPDATE_PORT_PAUSED_NUM(0)
    UPDATE_PORT_PAUSED_NUM(1)
    UPDATE_PORT_PAUSED_NUM(2)
    UPDATE_PORT_PAUSED_NUM(3)

	Register<bit<16>, _>(512, 0) re_port_enq_depth_win0;
	Register<bit<16>, _>(512, 0) re_port_enq_depth_win1;
	Register<bit<16>, _>(512, 0) re_port_enq_depth_win2;
	Register<bit<16>, _>(512, 0) re_port_enq_depth_win3;

#define UPDATE_PORT_ENQ_DEPTH(EP_IDX)										    \
	RegisterAction<_, _, bit<16>>(re_port_enq_depth_win##EP_IDX##)				\
						rae_update_port_enq_depth_win##EP_IDX## = {				\
        void apply(inout bit<16> value, out bit<16> output) {				    \
			output = 0;														    \
			if (eg_md.change_epoch == 1) {					                    \
				value = eg_intr_md.enq_qdepth[15:0];						    \
			}																    \
			else {															    \
				bit<16> in_v;												    \
				in_v = value;												    \
				value = value + eg_intr_md.enq_qdepth[15:0];				    \
				output = in_v;												    \
			}																    \
        }																	    \
    };																		    \
    action ae_update_re_port_enq_depth_win##EP_IDX##() {				        \
        eg_md.port_enq_qdepth = 												\
			rae_update_port_enq_depth_win##EP_IDX##.execute(eg_intr_md.egress_port);	\
	}																		    \
    action ae_upqn_win##EP_IDX##() {}                                           \
    table te_update_re_port_enq_depth_win##EP_IDX## {			                \
        key = {                                                                 \
            eg_md.epoch_idx: exact;                                             \
            eg_md.lock_flag: exact;                                             \
        }										                                \
        actions = { ae_update_re_port_enq_depth_win##EP_IDX##;		            \
					 ae_upqn_win##EP_IDX##; }								    \
		const entries = {													    \
            (##EP_IDX##, 0): ae_update_re_port_enq_depth_win##EP_IDX##();       \
		}																	    \
        const default_action = ae_upqn_win##EP_IDX##();						    \
    }								                                            \

    UPDATE_PORT_ENQ_DEPTH(0)
    UPDATE_PORT_ENQ_DEPTH(1)
    UPDATE_PORT_ENQ_DEPTH(2)
    UPDATE_PORT_ENQ_DEPTH(3)

//#define READ_PORT_METER(EP_IDX)												\
//	RegisterAction<_, _, bit<1>>(re_port_meter_win##EP_IDX##) 				\
//							rae_read_port_meter_win##EP_IDX## = {			\
//        void apply(inout bit<16> value, out bit<1> output) {				\
//			output = 0;													    \
//			if (value > PORT_METER_TH) {						            \
//				output = 1;													\
//			} 																\
//        }																	\
//	};																		\
//	action																\


// ---------------FORM the telemetry data---------------------------- 
//
//    Hash<bit<32>>(HashAlgorithm_t.IDENTITY) telem_data_fields_byte_0;
//    action ae_telemetry_data_gen_byte_0() {
//        eg_md.telem_data_byte_0 = telem_data_fields_byte_0.get({
//                //eg_md.ingress_port, // should bridged from intrinsic metadata
//                //eg_md.priority,
//                eg_md.pkt_num
//            });
//    }
//    table te_telemetry_data_gen_byte_0 {
//        actions = { ae_telemetry_data_gen_byte_0; }
//        size = 1;
//        const default_action = ae_telemetry_data_gen_byte_0();
//    }  
//
//    Hash<bit<32>>(HashAlgorithm_t.IDENTITY) telem_data_fields_byte_4;
//    action ae_telemetry_data_gen_byte_4() {
//        eg_md.telem_data_byte_4 = telem_data_fields_byte_4.get({
//                eg_md.paused_num // from intrinsic metadata
//            });
//    }
//    table te_telemetry_data_gen_byte_4 {
//        actions = { ae_telemetry_data_gen_byte_4; }
//        size = 1;
//        const default_action = ae_telemetry_data_gen_byte_4();
//    }
///*
//TODO: temp commented
//    Hash<bit<32>>(HashAlgorithm_t.IDENTITY) telem_data_fields_byte_8;
//    action ae_telemetry_data_gen_byte_8() {
//        eg_md.telem_data_byte_8 = telem_data_fields_byte_8.get({
//                hdr.udp.dst_port, // Should be
//                hdr.udp.src_port
//                // should be // bit<16> max_PSN_h; // from header
//                             // bit<16> QPN_h; // from header
//                // Using UDP for now, since no RDMA traffic currently.
//            });
//    }
//    table te_telemetry_data_gen_byte_8 {
//        actions = { ae_telemetry_data_gen_byte_8; }
//        size = 1;
//        const default_action = ae_telemetry_data_gen_byte_8();
//    }
//    Hash<bit<32>>(HashAlgorithm_t.IDENTITY) telem_data_fields_byte_12;
//    action ae_telemetry_data_gen_byte_12() {
//        eg_md.telem_data_byte_12 = telem_data_fields_byte_12.get({
//                hdr.udp.dst_port, // Should be
//                eg_md.pfc_paused_num
//                // should be // bit<8> QPN_l; // from header
//                             // bit<8> max_PSN_l; // from header
//                             // pfc_paused_num
//   // Using UDP for now, since no RDMA traffic currently.
//            });
//    }
//
//   */ 

    action ae_dump_info() {
//        hdr.telemetry_data_header.setValid();
//        hdr.telemetry_data_header.data_byte_0 = eg_md.telem_data_byte_0;
//        // hdr.telemetry_header.setValid();
        // hdr.telemetry_header.egress_timestamp = eg_intr_prsr_md.global_tstamp;
        // hdr.telemetry_header.flow_idx = eg_md.flow_idx;
        // hdr.telemetry_header.win_id = eg_md.win_id;
        // hdr.telemetry_header.telemetry_data = eg_md.telemetry_data;
    }
    table te_dump_info {
        actions = { ae_dump_info; }
        size = 1;
        const default_action = ae_dump_info();
    }
 
 /* 
    action ae_set_mirror(MirrorId_t egr_mir_ses) {
        eg_md.egr_mir_ses =  egr_mir_ses;
        eg_md.pkt_type = PKT_TYPE_MIRROR;
		eg_intr_dprsr_md.mirror_type = MIRROR_TYPE_E2E;	
		eg_md.mirror_data.mirror_flag= MIR_RECIRC_FLAG;	
		//eg_md.mirror_data.src_port = hdr.tcp.src_port;
		// eg_md.mirror_data.dst_port = hdr.tcp.dst_port;	
		// eg_md.mirror.ingress_port = eg_md.ingress_port;
		eg_md.mirror_data.egress_port = eg_intr_md.egress_port;
	//	eg_md.mirror_data.epoch_idx = eg_md.epoch_idx;
		eg_md.mirror_data.congst_contrb = eg_md.port_meter_rate;
		eg_md.mirror_data.egr_mir_ses = egr_mir_ses; 
		//hdr.tcp.dst_port = 0x04D3;	
	}
	table te_set_mirror {
        key = {
          //  eg_md.mirror_flag: exact;
			// hdr.ipv4.dst_ip : exact; 
			 hdr.tcp.dst_port : exact; // mirror pkts with specific dst_port
            // Using exact for now.
            // lpm requires considerable modification in API invoking
        }
        actions = {
			ae_set_mirror;
			ae_nop;
        }
		default_action = ae_nop;
    }
	action ae_mirror_gen_signal(MirrorId_t egr_mir_ses) {
        // enable to mirror
		eg_md.egr_mir_ses =  egr_mir_ses;
		eg_md.should_reset_signal = 1;
        eg_md.pkt_type = PKT_TYPE_MIRROR;
		eg_intr_dprsr_md.mirror_type = MIRROR_TYPE_E2E;	
		eg_md.mirror_data.mirror_flag= MIR_RECIRC_FLAG;	
		eg_md.mirror_data.egress_port = eg_intr_md.egress_port;
	}

	table te_mirror_gen_signal {
		key = {
			//eg_intr_md.enq_qdepth: range; 
            // bit<19>
			eg_md.can_signal: exact;
		}
		actions = {
			ae_mirror_gen_signal;
			ae_nop;
		}
//		default_action = ae_mirror_gen_signal(2);
		const entries = {
			(1): ae_mirror_gen_signal(2);
		}
		default_action = ae_nop;
	
	}
*/

    Register<bit<8>, _>(1, 0) re_lock_flag;

    RegisterAction<_, _, bit<1>>(re_lock_flag) rae_flip_lock_flag = {
        void apply(inout bit<8> value, out bit<1> output) {
            value = ~value;
            output = value[0:0];
        }
    };
	action ae_flip_lock_flag() {								
        eg_md.lock_flag = rae_flip_lock_flag.execute(0);	
	}																			
	
    RegisterAction<_, _, bit<1>>(re_lock_flag) rae_set_lock_flag = {
        void apply(inout bit<8> value, out bit<1> output) {
            value = 0xff;
            output = value[0:0];
        }
    };
	action ae_set_lock_flag() {								
        eg_md.lock_flag = rae_set_lock_flag.execute(0);	
    }																			
    
    RegisterAction<_, _, bit<1>>(re_lock_flag) rae_reset_lock_flag = {
        void apply(inout bit<8> value, out bit<1> output) {
            value = 0;
            output = value[0:0];
        }
    };
	action ae_reset_lock_flag() {								
        eg_md.lock_flag = rae_reset_lock_flag.execute(0);	
	}						

    RegisterAction<_, _, bit<1>>(re_lock_flag) rae_read_lock_flag = {
        void apply(inout bit<8> value, out bit<1> output) {
            output = value[0:0];
        }
    };
	action ae_read_lock_flag() {								
        eg_md.lock_flag = rae_read_lock_flag.execute(0);	
	}				
    
    table te_select_update_lock_flag {
        key = {
            hdr.ethernet.ether_type: exact;
            hdr.polling.TP_type: ternary;
            eg_md.comp_egress_port: ternary;
            eg_md.port_paused_num: range;
            eg_md.port_meter_rate: range;
        }
        actions = {
            ae_read_lock_flag;
            ae_set_lock_flag;
        }
        const entries = {
            (ETHERTYPE_IPV4, 	_, _, 0 .. 65535, 0 .. 65535) : ae_read_lock_flag();
            (ETHERTYPE_POLLING, 1, 0, 1 .. 65535, 0 .. 65535) : ae_set_lock_flag(); 
            (ETHERTYPE_POLLING, 1, 0, 0 .. 0,	  0 .. 65535) : ae_set_lock_flag(); 
            (ETHERTYPE_POLLING, 3, 0, 1 .. 65535, 0 .. 65535) : ae_set_lock_flag(); 
            (ETHERTYPE_POLLING, 3, 0, 0 .. 0, 	  0 .. 65535) : ae_set_lock_flag(); 
            (ETHERTYPE_POLLING, 2, 1, 1 .. 65535, 1 .. 65535) : ae_set_lock_flag(); 
            (ETHERTYPE_POLLING, 3, 1, 1 .. 65535, 1 .. 65535) : ae_set_lock_flag(); 
//			match (TP, comp_egress_port, if_paused, meter_value):
//				(b'01, 0, >0, _): lock, TP=11, copy2CPU, forward
//				(b'01, 0, =0, _): lock, TP=01, copy2CPU, forward
//				(b'11, 0, >0, _): lock, TP=11, copy2CPU, forward
//				(b'11, 0, =0, _): lock, TP=01, copy2CPU, forward
//				(b'10, 1, >0, >0): lock, TP=10, copy2CPU, forward
//				(b'11, 1, >0, >0): lock, TP=10, copy2CPU, forward

        }
        const default_action = ae_read_lock_flag();
    }

    Hash<bit<8>>(HashAlgorithm_t.IDENTITY) copy_8;	
    action ae_comp_egress_port() {
       eg_md.comp_egress_port = copy_8.get(hdr.polling.egress_port[7:0]) - (eg_intr_md.egress_port[7:0]); 
    }
    table te_comp_egress_port {
        key = {}
        actions = {
            ae_comp_egress_port;
        }
        const default_action = ae_comp_egress_port();
    }

    action ae_mark_and_copy_to_CPU(bit<2> TP_type) {
        //eg_md.lock_flag = rae_set_lock_flag.execute(0);//eg_md.lock_flag = 1;	
        hdr.polling.TP_type = TP_type; 

        eg_md.egr_mir_ses =  UPDATE_NOTIFY_MIRROR_SID;
        //eg_md.pkt_type = PKT_TYPE_MIRROR;
		eg_md.mirror_data.mirror_flag= MIR_CPU_FLAG;	
//		// 2 ports inserted at the same time will report compiler bug 
//        //eg_md.mirror_data.ingress_port = eg_md.bridged.ingress_port;
        eg_md.mirror_data.egress_port = eg_intr_md.egress_port;
        eg_intr_dprsr_md.mirror_type = MIRROR_TYPE_E2E;	
    }
	action ae_drop_polling() {
        eg_intr_dprsr_md.drop_ctl = 1;
	}
    table te_match_polling_TP_port {
        key = {
//	        eg_md.mirror_data.isValid(): exact;   
			// eg_md.mirror_data.mirror_flag= MIR_CPU_FLAG;	
 			hdr.polling.TP_type: exact;
            eg_md.comp_egress_port: range;
            eg_md.port_paused_num: range;
            eg_md.port_meter_rate: range;
        }
        actions = {
            ae_drop_polling;
            ae_mark_and_copy_to_CPU;
        }
        const entries = {
            (1, 0, 1 .. 65535, 0 .. 65535) : ae_mark_and_copy_to_CPU(3); 
            (1, 0, 0 .. 0,	  0 .. 65535) : ae_mark_and_copy_to_CPU(1); 
            (3, 0, 1 .. 65535, 0 .. 65535) : ae_mark_and_copy_to_CPU(3);  
            (3, 0, 0 .. 0, 	  0 .. 65535) : ae_mark_and_copy_to_CPU(1); 
            (2, 1..255, 1 .. 65535, 1 .. 65535) : ae_mark_and_copy_to_CPU(2); 
            (3, 1..255, 1 .. 65535, 1 .. 65535) : ae_mark_and_copy_to_CPU(2); 
//			match (TP, comp_egress_port, paused, meter_value):
//				(b'01, 0, >0, _): lock, TP=11, copy2CPU, forward
//				(b'01, 0, =0, _): lock, TP=01, copy2CPU, forward
//				(b'11, 0, >0, _): lock, TP=11, copy2CPU, forward
//				(b'11, 0, =0, _): lock, TP=01, copy2CPU, forward
//				(b'10, 1, >0, >0): lock, TP=10, copy2CPU, forward
//				(b'11, 1, >0, >0): lock, TP=10, copy2CPU, forward
        }
		const default_action = ae_drop_polling();
    }

    // for debug
	action ae_debug_dump() {
		hdr.polling.vf_protocol = eg_md.comp_egress_port; 
		hdr.polling.vf_src_port = eg_md.port_paused_num;
		hdr.polling.vf_dst_port = eg_md.port_meter_rate;
	}
	action ae_debug_nop() {

	}
	action ae_debug_drop() {
        eg_intr_dprsr_md.drop_ctl = 1;
	}
	table te_match_paused_and_send {
        key = {
        	eg_md.is_paused: exact;
		}
        actions = {
            ae_debug_nop;
			ae_debug_drop;
        }
        const entries = {
            (1) : ae_debug_nop(); // for debug 3 to 0
        }
		//const default_action = ae_drop_polling();	
        default_action = ae_debug_drop();
    }


	
	action ae_drop() {
        eg_intr_dprsr_md.drop_ctl = 1;
	}
   	table te_drop {
		key = {}
		actions = {ae_drop;}
		size = 1;
		default_action = ae_drop();
	}
    

	apply {
//		te_port_tuple_idx_calc.apply();
		// stage0
        // te_reltv_tstamp_extract.apply();
        // stage 1
        te_epoch_idx_gen.apply(); 
		te_update_change_epoch.apply();
		
        te_select_update_pkt_last_timer.apply();
		te_select_update_pause_timer.apply();
        
        te_port_tuple_idx_calc.apply();
        te_flow_idx_calc.apply();
			
        te_update_re_port_meter_win0.apply();	
        te_update_re_port_meter_win1.apply();	
		te_update_re_port_meter_win2.apply();	
		te_update_re_port_meter_win3.apply();	

        te_update_re_port_enq_depth_win0.apply();
        te_update_re_port_enq_depth_win1.apply();
        te_update_re_port_enq_depth_win2.apply();
        te_update_re_port_enq_depth_win3.apply();

        te_update_re_port_paused_num_win0.apply();
        te_update_re_port_paused_num_win1.apply();
        te_update_re_port_paused_num_win2.apply();
        te_update_re_port_paused_num_win3.apply();
        
        
        te_comp_egress_port.apply();
        te_select_update_lock_flag.apply();// Polling: set the bit; IPv4: read
        
        if (hdr.ethernet.ether_type == ETHERTYPE_IPV4) {
            // match lock to decide wether to write
            // te_update_re_telemetry_egress_port.apply();  
	      	te_update_re_telemetry_dst_ip.apply();
			te_update_re_telemetry_src_ip.apply();
			// te_update_re_telemetry_dst_port.apply();
			te_update_re_telemetry_src_port.apply();

	        te_update_re_telemetry_pkt_num_win0.apply();
	        te_update_re_telemetry_pkt_num_win1.apply();
	        te_update_re_telemetry_pkt_num_win2.apply();
	        te_update_re_telemetry_pkt_num_win3.apply();
	        
            te_update_re_telemetry_unpaused_enq_qdepth_win0.apply();
            te_update_re_telemetry_unpaused_enq_qdepth_win1.apply();
            te_update_re_telemetry_unpaused_enq_qdepth_win2.apply();
            te_update_re_telemetry_unpaused_enq_qdepth_win3.apply();

	        te_update_re_telemetry_paused_num_win0.apply();
	        te_update_re_telemetry_paused_num_win1.apply();
	        te_update_re_telemetry_paused_num_win2.apply();
	        te_update_re_telemetry_paused_num_win3.apply();
	
		}
        else if (hdr.ethernet.ether_type == ETHERTYPE_POLLING) {
        
            if (eg_md.mirror_data.mirror_flag != MIR_CPU_FLAG) {
				 te_match_polling_TP_port.apply();
			//	te_debug_match_polling_TP_port.apply();
        	}
	
		}

	}


}


// ---------------------------------------------------------------------------
// Egress deparser
// ---------------------------------------------------------------------------
control SwitchEgressDeparser(
        packet_out pkt,
        inout custom_header_t hdr,
        in egress_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_intr_dprsr_md) { 
        
    
    Checksum() ipv4_csum;
    Checksum() icmp_csum;
    // IPv6 does not have checksum field
    Checksum() tcp_csum;
    Mirror() mirror;
    apply {
        hdr.ipv4.checksum = ipv4_csum.update({
            hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv,
            hdr.ipv4.total_len, hdr.ipv4.identification, hdr.ipv4.flags,
            hdr.ipv4.frag_offset, hdr.ipv4.ttl, hdr.ipv4.protocol,
//            // Skip hdr.ipv4.checksum,
//            // hdr.ipv4.checksum,
            hdr.ipv4.src_ip, hdr.ipv4.dst_ip
        });

        // recompute from 0 instead of incremetally for simplicity
        // not valid in deparser
        // hdr.ipv4.checksum = 16w0;
        // ipv4_csum.clear();           // prepare checksum unit
        // ipv4_csum.update(hdr.ipv4); // write header
        
		hdr.icmp.checksum = icmp_csum.update({
            eg_md.icmp_csum, hdr.icmp.id, hdr.icmp.seq_no
        });

        hdr.tcp.checksum = tcp_csum.update({
// #if __IP_TYPE__ == 6
//             hdr.ipv6.src_ip, hdr.ipv6.dst_ip,
// #endif
           hdr.ipv4.src_ip, hdr.ipv4.dst_ip,
            hdr.tcp.src_port, hdr.tcp.dst_port, hdr.tcp.seq_no, hdr.tcp.ack_no,
            hdr.tcp.data_offset, hdr.tcp.res, hdr.tcp.urg, hdr.tcp.ack,
            hdr.tcp.psh, hdr.tcp.rst, hdr.tcp.syn, hdr.tcp.fin,
            eg_md.tcp_csum
        });
        // if (eg_intr_dprsr_md.mirror_type == MIRROR_TYPE_E2E) {
        //     mirror.emit<mirror_h>(
        //         eg_md.update_notification_mirror_sid, eg_md.mirror
        //     );
        // }

        pkt.emit(hdr);
        if (eg_intr_dprsr_md.mirror_type == MIRROR_TYPE_E2E) {
            mirror.emit<mirror_data_h>(eg_md.egr_mir_ses, eg_md.mirror_data);
        }
		
//         pkt.emit(hdr.ethernet);
//         pkt.emit(hdr.ipv4);
//         pkt.emit(hdr.ipv6);
//         pkt.emit(hdr.tcp);
//         pkt.emit(hdr.udp);
////         pkt.emit(hdr.timestamp);
   
		
	 }
}


// ---------------------------------------------------------------------------
// Assemble pipeline and switch
// ---------------------------------------------------------------------------
Pipeline(
    SwitchIngressParser(),
    SwitchIngress(),
    SwitchIngressDeparser(),
    SwitchEgressParser(),
    SwitchEgress(),
    SwitchEgressDeparser()
) pipe;

Switch(pipe) main;