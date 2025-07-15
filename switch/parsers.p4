/*******************************************************************************
 * BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
 *
 * Copyright (c) 2018-2019 Barefoot Networks, Inc.
 * All Rights Reserved.
 *
 * NOTICE: All information contained herein is, and remains the property of
 * Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
 * technical concepts contained herein are proprietary to Barefoot Networks,
 * Inc.
 * and its suppliers and may be covered by U.S. and Foreign Patents, patents in
 * process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material is
 * strictly forbidden unless prior written permission is obtained from
 * Barefoot Networks, Inc.
 *
 * No warranty, explicit or implicit is provided, unless granted under a
 * written agreement with Barefoot Networks, Inc.
 *
 *
 ******************************************************************************/
#ifndef _PARSERS_
#define _PARSERS_
#include "headers.p4"
#include "../config.h"


parser TofinoIngressParser(
        packet_in pkt,
        out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) {
            1 : parse_resubmit;
            0 : parse_port_metadata;
        }
    }

    state parse_resubmit {
        //pkt.extract(ig_md.resubmit_hdr);
        transition reject;
    }

	
	
    state parse_port_metadata {
        pkt.advance(PORT_METADATA_SIZE);
        transition accept;
    }
}

parser TofinoEgressParser(
        packet_in pkt,
        out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

// Empty egress parser/control blocks
parser EmptyEgressParser<H, M>(
        packet_in pkt,
        out H hdr,
        out M eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        transition accept;
    }
}
/*
parser StackParser(packet_in pkt, out custom_header_t hdr) {
    state start { // parse Ethernet
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_ARP  : parse_arp;
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_IPV6 : parse_ipv6;
            default : reject;
        }
    }

    state parse_arp {
        pkt.extract(hdr.arp);
        transition select(hdr.arp.hw_type, hdr.arp.proto_type) {
            (0x0001, ETHERTYPE_IPV4) : parse_arp_ipv4;
            default : reject;
        }
    }

    state parse_arp_ipv4 {
        pkt.extract(hdr.arp_ipv4);
        transition accept;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_ICMP : parse_icmp;
            IP_PROTOCOLS_TCP  : parse_tcp;
            IP_PROTOCOLS_UDP  : parse_udp;
            default : accept;
        }
    }

   
    state parse_ipv6 {
        pkt.extract(hdr.ipv6);
        transition select(hdr.ipv6.next_hdr) {
            IP_PROTOCOLS_ICMP : parse_icmp;
            IP_PROTOCOLS_TCP  : parse_tcp;
            IP_PROTOCOLS_UDP  : parse_udp;
            default : accept;
        }
    }

    state parse_icmp {
        pkt.extract(hdr.icmp);
        transition accept;
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }
}
*/


parser MonicaIngressStackParser(packet_in pkt,
								 out custom_header_t hdr,
								 out ingress_metadata_t ig_md) {
    state start { // parse Ethernet
		ig_md.bridged.setValid();
		mirror_flag_t mirror_flag = pkt.lookahead<mirror_flag_t>();
    	transition select(mirror_flag){    
//	    	MIR_RECIRC_FLAG: parse_mirror_data;
	    	MIR_CPU_FLAG: parse_mirror_data;
            default : parse_ethernet;
        }
	}

	
	state parse_mirror_data {
		pkt.extract(ig_md.mirror_data);
		transition parse_ethernet;	
	}
	state parse_ethernet {
		pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
//			ETHERTYPE_ARP  : parse_arp;
            ETHERTYPE_IPV4 : parse_ipv4;
//            ETHERTYPE_IPV6 : parse_ipv6;
            ETHERTYPE_PAUSE: parse_pause; // PFC or PAUSE frame
//			ETHERTYPE_SIGNAL: parse_signal;
//			ETHERTYPE_SIGNAL_BROADCAST: parse_signal;
            ETHERTYPE_POLLING: parse_polling; 
			default : accept;
        }
    }
	state parse_pause {
		pkt.extract(hdr.pause);
		transition accept;
	}
    state parse_polling {
        pkt.extract(hdr.polling);
        transition accept;
    }
//    state parse_arp {
//        pkt.extract(hdr.arp);
//        transition select(hdr.arp.hw_type, hdr.arp.proto_type) {
//            (0x0001, ETHERTYPE_IPV4) : parse_arp_ipv4;
//            default : reject;
//        }
//    }
//	state parse_signal {
//		pkt.extract(hdr.signal);
//		transition accept;
//	}

//    state parse_arp_ipv4 {
//        pkt.extract(hdr.arp_ipv4);
//        transition accept;
//    }
//
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_ICMP : parse_icmp;
            IP_PROTOCOLS_TCP  : parse_tcp;
            IP_PROTOCOLS_UDP  : parse_udp;
            default : accept;
        }
    }
   
//    state parse_ipv6 {
//        pkt.extract(hdr.ipv6);
//        transition select(hdr.ipv6.next_hdr) {
//            IP_PROTOCOLS_ICMP : parse_icmp;
//            IP_PROTOCOLS_TCP  : parse_tcp;
//            IP_PROTOCOLS_UDP  : parse_udp;
//            default : accept;
//        }
//    }

    state parse_icmp {
        pkt.extract(hdr.icmp);
        transition accept;
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }
}

parser MonicaEgressStackParser(packet_in pkt,
                        	out custom_header_t hdr,
                        	out egress_metadata_t eg_md) {
    
//	state start { // parse bridged and Ethernet
//		pkt.extract(eg_md.bridged);
//		transition parse_ethernet;
//   }

    Checksum() icmp_csum;
    Checksum() tcp_csum;
	state start { // parse Ethernet
		mirror_flag_t mirror_flag = pkt.lookahead<mirror_flag_t>();
    	transition select(mirror_flag){    
	    	//MIR_RECIRC_FLAG: parse_mirror_data;
	    	MIR_CPU_FLAG: parse_mirror_data;
            default : parse_bridged;
        }
    }

	state parse_mirror_data {
		pkt.extract(eg_md.mirror_data);
		transition parse_ethernet;	
	}
	state parse_bridged {
		pkt.extract(eg_md.bridged);
		transition parse_ethernet;
	}
	

	state parse_ethernet {
		pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
//			ETHERTYPE_ARP  : parse_arp;
            ETHERTYPE_IPV4 : parse_ipv4;
//            ETHERTYPE_IPV6 : parse_ipv6;
            ETHERTYPE_PAUSE: parse_pause;
            ETHERTYPE_POLLING: parse_polling;
//			ETHERTYPE_SIGNAL: parse_signal;
//			ETHERTYPE_SIGNAL_BROADCAST: parse_signal;
			default : accept;
			// difference is target-specific
			// In tofino: seems like only an error set
			// pkt still transmit instead of drop?
        }
    }
//    state parse_arp {
//        pkt.extract(hdr.arp);
//        transition select(hdr.arp.hw_type, hdr.arp.proto_type) {
//            (0x0001, ETHERTYPE_IPV4) : parse_arp_ipv4;
//            default : reject;
//        }
//    }
//
//	state parse_signal {
//		pkt.extract(hdr.signal);
//		transition accept;
//	}
//	state parse_signal_broadcast {
//		pkt.extract(hdr.signal_broadcast);
//		transition accept;
//	}
	state parse_pause {
		pkt.extract(hdr.pause);
//		//eg_md.real_pause_time = (bit<32>)hdr.pause.pause_time ;
		transition accept;
	}

    state parse_polling {
        pkt.extract(hdr.polling);
        transition accept;
    }
//    state parse_arp_ipv4 {
//        pkt.extract(hdr.arp_ipv4);
//        transition accept;
//    }
//
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
  		tcp_csum.subtract({ hdr.ipv4.src_ip, hdr.ipv4.dst_ip });
		transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_ICMP : parse_icmp;
            IP_PROTOCOLS_TCP  : parse_tcp;
            IP_PROTOCOLS_UDP  : parse_udp;
            default : accept;
        }
    }

   
//    state parse_ipv6 {
//        pkt.extract(hdr.ipv6);
//        tcp_csum.subtract({ hdr.ipv6.src_ip, hdr.ipv6.dst_ip });
//		transition select(hdr.ipv6.next_hdr) {
//            IP_PROTOCOLS_ICMP : parse_icmp;
//            IP_PROTOCOLS_TCP  : parse_tcp;
//            IP_PROTOCOLS_UDP  : parse_udp;
//            default : accept;
//        }
//    }
//
    state parse_icmp {
        pkt.extract(hdr.icmp);
		icmp_csum.subtract({ hdr.icmp.checksum });
        icmp_csum.subtract({ hdr.icmp.id, hdr.icmp.seq_no });
        eg_md.icmp_csum = icmp_csum.get();
        transition accept;
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
		tcp_csum.subtract({ hdr.tcp.checksum });
        tcp_csum.subtract({
            hdr.tcp.src_port, hdr.tcp.dst_port, hdr.tcp.seq_no, hdr.tcp.ack_no,
            hdr.tcp.data_offset, hdr.tcp.res, hdr.tcp.urg,
            hdr.tcp.ack, hdr.tcp.psh, hdr.tcp.rst, hdr.tcp.syn, hdr.tcp.fin
        });
        eg_md.tcp_csum = tcp_csum.get();
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }
}
// control SwitchIngressDeparser(
//         packet_out pkt,
//         inout custom_header_t hdr,
//         in ingress_metadata_t ig_md,
//         in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) { 
    
//     apply {
//         pkt.emit(ig_md.bridged);
//         pkt.emit(hdr);
//         // pkt.emit(hdr.ethernet);
//         // pkt.emit(hdr.ipv4);
//         // pkt.emit(hdr.ipv6);
//         // pkt.emit(hdr.tcp);
//         // pkt.emit(hdr.udp);
//         // pkt.emit(hdr.timestamp);
//     }
// }

parser MinamotoEgressParser(packet_in pkt,
                        out custom_header_t hdr,
                        out egress_metadata_t eg_md) {
    Checksum() icmp_csum;
    Checksum() tcp_csum;
    Checksum() ipv4_csum;
    state start {
        transition accept;
    }

//     state start {
//         internal_metadata_t internal_md = pkt.lookahead<internal_metadata_t>();
//         transition select(internal_md.pkt_label) {
//             PKT_LABEL_UPDATE_NOTIFY: parse_mirror;
//             default: parse_bridged;
//         }
//     }

//     state parse_mirror {
//         pkt.extract(eg_md.mirror);
//         transition parse_ethernet;
//     }

//     state parse_bridged {
//         pkt.extract(eg_md.bridged);
//         transition parse_ethernet;
//     }

//     state parse_ethernet {
//         pkt.extract(hdr.ethernet);
//         eg_md.swp_mac = hdr.ethernet.src_mac;
//         transition select(hdr.ethernet.ether_type) {
//             ETHERTYPE_ARP  : parse_arp;
//             ETHERTYPE_IPV4 : parse_ipv4;
//             ETHERTYPE_IPV6 : parse_ipv6;
//             // ETHERTYPE_ITEMPLATE : parse_ipv4;
//             default : reject;
//         }
//     }

//     state parse_arp {
//         pkt.extract(hdr.arp);
//         transition select(hdr.arp.hw_type, hdr.arp.proto_type) {
//             (0x0001, ETHERTYPE_IPV4) : parse_arp_ipv4;
//             default : reject;
//         }
//     }

//     state parse_arp_ipv4 {
//         pkt.extract(hdr.arp_ipv4);
//         transition accept;
//     }

//     state parse_ipv4 {
//         pkt.extract(hdr.ipv4);
// #if __IP_TYPE__ != 6 // Default IPv4
//         eg_md.swp_ip = hdr.ipv4.src_ip;
// #endif
//         tcp_csum.subtract({ hdr.ipv4.src_ip, hdr.ipv4.dst_ip });
//         transition select(hdr.ipv4.protocol) {
//             IP_PROTOCOLS_ICMP : parse_icmp;
//             IP_PROTOCOLS_TCP  : parse_tcp;
//             IP_PROTOCOLS_UDP  : parse_udp;
//             default : accept;
//         }
//     }

//     state parse_ipv6 {
//         pkt.extract(hdr.ipv6);
// #if __IP_TYPE__ == 6
//         eg_md.swp_ip = hdr.ipv6.src_ip;
// #endif
//         tcp_csum.subtract({ hdr.ipv6.src_ip, hdr.ipv6.dst_ip });
//         transition select(hdr.ipv6.next_hdr) {
//             IP_PROTOCOLS_ICMP : parse_icmp;
//             IP_PROTOCOLS_TCP  : parse_tcp;
//             IP_PROTOCOLS_UDP  : parse_udp;
//             default : accept;
//         }
//     }

//     state parse_icmp {
//         pkt.extract(hdr.icmp);
//         icmp_csum.subtract({ hdr.icmp.checksum });
//         icmp_csum.subtract({ hdr.icmp.id, hdr.icmp.seq_no });
//         eg_md.icmp_csum = icmp_csum.get();
//         transition accept;
//     }

//     state parse_tcp {
//         pkt.extract(hdr.tcp);
//         eg_md.swp_port = hdr.tcp.src_port;
//         eg_md.tmp_seq = hdr.tcp.seq_no;
//         tcp_csum.subtract({ hdr.tcp.checksum });
//         tcp_csum.subtract({
//             hdr.tcp.src_port, hdr.tcp.dst_port, hdr.tcp.seq_no, hdr.tcp.ack_no,
//             hdr.tcp.data_offset, hdr.tcp.res, hdr.tcp.urg,
//             hdr.tcp.ack, hdr.tcp.psh, hdr.tcp.rst, hdr.tcp.syn, hdr.tcp.fin
//         });
//         eg_md.tcp_csum = tcp_csum.get();
//         transition accept;
//     }

//     state parse_udp {
//         pkt.extract(hdr.udp);
//         transition accept;
//     }
}

control EmptyEgressDeparser<H, M>(
        packet_out pkt,
        inout H hdr,
        in M eg_md,
        in egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md) {
    apply {}
}

control EmptyEgress<H, M>(
        inout H hdr,
        inout M eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {
    apply {}
}

#endif /* _UTIL */
