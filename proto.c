#include "proto.h"
#include <stdio.h>

#define ntos(input) ((input)[0] << 8 | (input)[1])
#define ntoi(input) ((input)[0] << 24 | ((input)[1] << 16) | ((input)[2] << 8) || (input)[3])


void parseProtoHeader(const unsigned char *packet_content, struct parse_struct * parse_res) {
    if (parse_res == NULL) {
        return;
    }

    // eth
    struct eth_header * eth_tmp = (struct eth_header *)packet_content;
    switch (ntos((unsigned char *)(&eth_tmp->type))) {
        case CODE_ETH_ARP: {
            parse_res->ETH_type = ETH_ARP;
            break;
        }
        case CODE_ETH_ARP_REPLY: {
            parse_res->ETH_type = ETH_ARP_REPLAY;
            break;
        }
        case CODE_ETH_IP4: {
            parse_res->ETH_type = ETH_IP4;
            break;
        }
        case CODE_ETH_IP6: {
            parse_res->ETH_type = ETH_IP6;
            break;
        }
        default: {
            parse_res->ETH_type = OTHER;
            break;
        }
    }

    for (unsigned i = 0; i < 6; i++) {
        parse_res->src_mac[i] = eth_tmp->src_mac[i];
        parse_res->dst_mac[i] = eth_tmp->dst_mac[i];
    }

    // ip
    if (parse_res->ETH_type == ETH_IP4 || parse_res->ETH_type == ETH_IP6) {
        if (parse_res->ETH_type == ETH_IP4) {
            struct ip4_header * ip_temp = (struct ip4_header *)(packet_content + eth_len);
            
            for (unsigned i = 0; i < 4; i++) {
                parse_res->src_ip[i] = ip_temp->sourceIP[i];
                parse_res->dst_ip[i] = ip_temp->destIP[i];
            }

            if (ip_temp->protocol == CODE_IP_ICMP) {
                parse_res->IP_type = IP_ICMP;
                parse_res->TRANS_type = TRANS_NONE;
                parse_res->APP_type = APP_NONE;
            } else if (ip_temp->protocol == CODE_IP_TCP) {
                parse_res->IP_type = IP_IP4;
                parse_res->TRANS_type = TRANS_TCP;
                struct tcp_header * tcp_temp = (struct tcp_header *)(packet_content + eth_len + ip4_len);
                parse_res->sport = ntos((unsigned char *)(&tcp_temp->sport));
                parse_res->dport = ntos((unsigned char *)(&tcp_temp->dport));
                parse_res->seq = ntoi((unsigned char *)(&tcp_temp->seq));
                parse_res->ack = ntoi((unsigned char *)(&tcp_temp->ack));

                switch (parse_res->sport)
                {
                    case CODE_APP_DNS:
                        parse_res->APP_type = APP_DNS;
                        break;
                    case CODE_APP_HTTP:
                        parse_res->APP_type = APP_HTTP;
                        break;
                    case CODE_APP_HTTPS:
                        parse_res->APP_type = APP_HTTPS;
                        break;
                    case CODE_APP_SMTP:
                        parse_res->APP_type = APP_SMTP;
                        break;
                    
                    default:
                        parse_res->APP_type = APP_NONE;
                }

                switch (parse_res->dport)
                {
                    case CODE_APP_DNS:
                        parse_res->APP_type = APP_DNS;
                        break;
                    case CODE_APP_HTTP:
                        parse_res->APP_type = APP_HTTP;
                        break;
                    case CODE_APP_HTTPS:
                        parse_res->APP_type = APP_HTTPS;
                        break;
                    case CODE_APP_SMTP:
                        parse_res->APP_type = APP_SMTP;
                        break;
                }
                
            } else if (ip_temp->protocol == CODE_IP_UDP) {
                parse_res->IP_type = IP_IP4;
                parse_res->TRANS_type = TRANS_UDP;
                struct udp_header * udp_temp = (struct udp_header *)(packet_content + eth_len + ip4_len);
                parse_res->sport = ntos((unsigned char *)(&udp_temp->sport));
                parse_res->dport = ntos((unsigned char *)(&udp_temp->dport));

                switch (parse_res->sport)
                {
                    case CODE_APP_DNS:
                        parse_res->APP_type = APP_DNS;
                        break;
                    
                    default:
                        parse_res->APP_type = APP_NONE;
                }

                switch (parse_res->dport)
                {
                    case CODE_APP_DNS:
                        parse_res->APP_type = APP_DNS;
                        break;
                }
            } else {
                parse_res->IP_type = IP_IP4;
                parse_res->TRANS_type = TRANS_NONE;
            }

        } else {
            struct ip6_header * ip_temp = (struct ip6_header *)(packet_content + eth_len);
            for (unsigned i = 0; i < 16; i++) {
                parse_res->src_ip[i] = ip_temp->sourceIP[i];
                parse_res->dst_ip[i] = ip_temp->destIP[i];
            }
            parse_res->IP_type = IP_IP6;
            parse_res->TRANS_type = TRANS_NONE;
        }
    } else {
        parse_res->IP_type = IP_NONE;
        parse_res->TRANS_type = TRANS_NONE;
    }


}
