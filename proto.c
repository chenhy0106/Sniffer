#include "proto.h"
#include <stdio.h>

#define ntos(input) ((input)[0] << 8 | (input)[1])
#define ntoi(input) ((input)[0] << 24 | ((input)[1] << 16) | ((input)[2] << 8) | (input)[3])


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
            parse_res->ETH_type = ETH_ARP_REPLY;
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

            parse_res->ip_len = ntos((unsigned char *)(&ip_temp->total_len));
            parse_res->ttl = ip_temp->ttl;

            if (ip_temp->protocol == CODE_IP_ICMP) {
                parse_res->IP_type = IP_ICMP;
                parse_res->TRANS_type = TRANS_NONE;
                parse_res->APP_type = APP_NONE;
                struct icmp_header * icmp_temp = (struct icmp_header *)(packet_content + eth_len + ip4_len);
                switch (icmp_temp->type)
                {
                case CODE_ICMP_PING_REQ:
                    parse_res->icmp_type = ICMP_PING_REQ;
                    break;
                case CODE_ICMP_PING_RLY:
                    parse_res->icmp_type = ICMP_PING_RLY;
                    break;
                case CODE_ICMP_TIMEOUT:
                    parse_res->icmp_type = ICMP_TIMEOUT;
                    break;
                case CODE_ICMP_UA: {
                    if (icmp_temp->code == CODE_ICMP_UA_NET) {
                        parse_res->icmp_type = ICMP_NET_UA;
                    } else if (icmp_temp->code == CODE_ICMP_UA_HOST) {
                        parse_res->icmp_type = ICMP_HOST_UA;
                    }
                    break;
                }
                case CODE_ICMP_REDIR:
                    parse_res->icmp_type = ICMP_REDIR;
                    break;
                }
                parse_res->icmp_code_int = icmp_temp->type;
                parse_res->icmp_type_int = icmp_temp->code;
            } else if (ip_temp->protocol == CODE_IP_TCP) {
                parse_res->IP_type = IP_IP4;
                parse_res->TRANS_type = TRANS_TCP;
                struct tcp_header * tcp_temp = (struct tcp_header *)(packet_content + eth_len + ip4_len);
                parse_res->sport = ntos((unsigned char *)(&tcp_temp->sport));
                parse_res->dport = ntos((unsigned char *)(&tcp_temp->dport));
                parse_res->seq = ntoi((unsigned char *)(&tcp_temp->seq));
                parse_res->ack = ntoi((unsigned char *)(&tcp_temp->ack));
                u_char flag = tcp_temp->flags;
                parse_res->SYN = ((flag & 0x2) != 0);
                parse_res->FIN = ((flag & 0x1) != 0);
                parse_res->wind_size = ntos((unsigned char *)(&tcp_temp->wind_size));
                parse_res->check_sum = ntos((unsigned char *)(&tcp_temp->check_sum));

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

                char is_udp = 0;
                switch (parse_res->sport)
                {
                    case CODE_APP_DNS:
                        parse_res->APP_type = APP_DNS;
                        is_udp = 1;
                        break;
                    
                    default:
                        parse_res->APP_type = APP_NONE;
                }

                switch (parse_res->dport)
                {
                    case CODE_APP_DNS:
                        parse_res->APP_type = APP_DNS;
                        is_udp = 1;
                        break;
                }

                if (is_udp) {
                    struct dns_header * dns_temp = (struct dns_header *) udp_temp + udp_len;
                    parse_res->trans_ID = ntos((unsigned char *)(&dns_temp->trans_ID));
                    parse_res->flags = ntos((unsigned char *)(&dns_temp->flags));
                    parse_res->question = ntos((unsigned char *)(&dns_temp->question));
                    parse_res->answer_RRs = ntos((unsigned char *)(&dns_temp->answer_RRs));
                    parse_res->Authority_RRs = ntos((unsigned char *)(&dns_temp->Authority_RRs));
                    parse_res->Additional_RRs = ntos((unsigned char *)(&dns_temp->Additional_RRs));
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
            parse_res->ip_len = ntos((unsigned char *)(ip_temp + 4));
            parse_res->IP_type = IP_IP6;
            parse_res->TRANS_type = TRANS_NONE;
        }
    } else {
        parse_res->IP_type = IP_NONE;
        parse_res->TRANS_type = TRANS_NONE;

        struct arp_header* arp_tmp = (struct arp_header *)(packet_content + eth_len);
        parse_res->hardware_type = ntos((unsigned char *)(&arp_tmp->hardware_type));
        parse_res->proto_type = ntos((unsigned char *)(&arp_tmp->proto_type));
        parse_res->op_code = ntos((unsigned char *)(&arp_tmp->op_code));

        for (unsigned i = 0; i < 6; i++) {
            parse_res->arp_src_mac[i] = arp_tmp->src_mac[i];
            parse_res->arp_dst_mac[i] = arp_tmp->dst_mac[i];
        }

        for (unsigned i = 0; i < 4; i++) {
            parse_res->arp_src_ip[i] = arp_tmp->src_ip[i];
            parse_res->arp_dst_ip[i] = arp_tmp->dst_ip[i];
        }
    }


}
