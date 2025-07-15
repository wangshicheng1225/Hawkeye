#include <arpa/inet.h>
#include <byteswap.h>
#include <dirent.h>
#include <endian.h>
#include <getopt.h>
#include <ifaddrs.h>
#include <inttypes.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/ether.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "detection_agent.h"

extern struct polling_config_t polling_config;
extern struct config_t config;


int init_polling_pkt() {
    struct ifreq if_idx;
    struct ifreq if_mac;
    struct ifreq if_ip;
    struct arpreq mac_req;
    char if_name[IFNAMSIZ - 1] = "enp3s0f0s0";
    int sockfd;
    

    polling_config.send_buf = (char *)malloc(BUF_SIZ);
    /* Open RAW socket to send on */
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
        fprintf(stderr, "init polling socket\n");
        return 1;
    }

    /* Get the index of the network device */
    memset(&if_idx, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, if_name, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0) {
        fprintf(stderr, "SIOCGIFINDEX\n");
        return 1;
    }

    /* Get the MAC address of the network device */
    memset(&if_mac, 0, sizeof(struct ifreq));
    strncpy(if_mac.ifr_name, if_name, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0) {
        fprintf(stderr, "SIOCGIFHWADDR\n");
        return 1;
    }

    /* Get the IP address of the network device */
    memset(&if_ip, 0, sizeof(struct ifreq));
    if_ip.ifr_addr.sa_family = AF_INET;
    strncpy(if_ip.ifr_name, if_name, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFADDR, &if_ip) < 0) {
        fprintf(stderr, "fuck SIOCGIFADDR\n");
        return 1;
    }

    polling_config.sockfd = sockfd;
    memset(polling_config.send_buf, 0, BUF_SIZ);
    memcpy(&polling_config.eh.ether_shost, &(if_mac.ifr_hwaddr.sa_data), 6);

    /* Get the MAC address of the target */
    memset(&mac_req, 0, sizeof(mac_req));
    struct sockaddr_in *sin = (struct sockaddr_in *)&mac_req.arp_pa;
    sin->sin_family = AF_INET;
    
    struct in_addr addr;
    addr.s_addr = ((uint32_t)config.server_name[0] << 24) |
                  ((uint32_t)config.server_name[1] << 16) |
                  ((uint32_t)config.server_name[2] << 8)  |
                  ((uint32_t)config.server_name[3]);
    addr.s_addr = htonl(addr.s_addr);
    sin->sin_addr.s_addr = addr.s_addr;


    strncpy(mac_req.arp_dev, if_name, sizeof(mac_req.arp_dev) - 1);
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (ioctl(sock, SIOCGARP, &mac_req) < 0) {
        fprintf(stderr, "SIOCGARP\n");
        close(sock);
        return 1;
    }
    close(sock);
    if (mac_req.arp_flags & ATF_COM) {
        memcpy(polling_config.eh.ether_dhost,
               (unsigned char *)mac_req.arp_ha.sa_data, ETH_ALEN);
    }

    polling_config.eh.ether_type = htons(0x6888);

    polling_config.ph.TP_type = 1;
    polling_config.ph.padding_0 = 0;
    polling_config.ph.ingress_port_low = 0xff;
    polling_config.ph.ingress_port_high = 1;
    polling_config.ph.padding_1 = 0;
    polling_config.ph.egress_port_low = 0xff;
    polling_config.ph.egress_port_high = 1;
    polling_config.ph.padding_2 = 0;
    polling_config.ph.vf_src_ip =
        ((struct sockaddr_in *)&if_ip.ifr_addr)->sin_addr.s_addr;
    polling_config.ph.vf_dst_ip = inet_addr(config.server_name);
    polling_config.ph.vf_src_port = htons(config.udp_sport);
    polling_config.ph.vf_dst_port = htons(4791);
    polling_config.ph.vf_protocol = 17;

    /* Index of the network device */
    polling_config.sa.sll_ifindex = if_idx.ifr_ifindex;
    polling_config.sa.sll_protocol = htons(ETH_P_ALL);

    return 0;
}

int send_polling_pkt(uint8_t event_id) {
    int tx_len = 0;
    polling_config.ph.event_id = event_id;
    memcpy(polling_config.send_buf, &polling_config.eh,
           sizeof(struct ether_header));
    tx_len += sizeof(struct ether_header);
    memcpy(polling_config.send_buf + tx_len, &polling_config.ph,
           sizeof(struct polling_header));
    tx_len += sizeof(struct polling_header);
    // printf("send polling packet\n");

    if (sendto(polling_config.sockfd, polling_config.send_buf, tx_len, 0,
               (struct sockaddr *)&polling_config.sa,
               sizeof(struct sockaddr_ll)) < 0) {
        fprintf(stderr, "sendto\n");
        return 1;
    }
    free(polling_config.send_buf);
    return 0;
}