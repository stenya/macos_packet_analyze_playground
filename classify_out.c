#include <netinet/ip.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <stdio.h>

#include "inc/pktap.h"

#include "checksum.c"
#include "print_frame_helpers.c"

#include "do_bpf.h"

#include "config.h"

#include "inject.c"

unsigned char buffer[sizeof(struct ether_header) + 0xFFFF] = {0};


int                      _handler_inject_type       = INJECT_TYPE_BPF;
//int                      _handler_inject_type       = INJECT_TYPE_PCAP;
struct inject_handler   _handler_inject_if_default;

/*
#define _USE_BPF_
#ifdef _USE_BPF_
    int     handle_default_if_bpf_fd = 0;
#else
    pcap_t *handle_default_if_pcap  = NULL;
#endif
*/

int injectToDefaultInterface(unsigned char* ipData, unsigned int len);

int classify_openForInjection()
{    
    if (inject_open(_handler_inject_type, IF_DEFAULT_NAME, &_handler_inject_if_default) != 0) {
        fprintf(stderr, "Couldn't open device: %s\n", IF_DEFAULT_NAME);
        return -1;
    }
    return 0;
}

int closeForInjection() {
    if (inject_close(&_handler_inject_if_default) != 0) {
        fprintf(stderr, "Error closing injection handler\n");
        return -1;
    }
    return 0;
}

int classify_func(const struct pktap_header *pktapHdr, unsigned char* ipData, unsigned int len) 
{
    if (pktapHdr == NULL || ipData == NULL) 
        return -1;

    // TODO: currently we are using only IPV4. We must support IPv6 also!
    if (len < sizeof(struct ip))
        return -2;

    // ------------------------------------------------ DEBUG
    struct ip *ip4Hdr   = NULL;
    if (pktapHdr->pth_protocol_family == AF_INET) 
    {
        ip4Hdr   = (struct ip *)ipData;
        if (strcmp(inet_ntoa(ip4Hdr->ip_src), "93.184.216.34")==0)
        {
            printf("classify: !===>>>GOT RESPONSE!\n");
            printf("classify:(((((((<<<<<<<<<<<<<<<<<<<<<<<<\n");
            print_pktap_header_all_details(pktapHdr, ipData, len);
            printf("classify:)))))))>>>>>>>>>>>>>>>>>>>>>>>>\n");
        }    
        if (strcmp(inet_ntoa(ip4Hdr->ip_dst), "93.184.216.34")==0)
        {
            printf("classify:====>>> sending...\n");
            printf("classify:(((((((<<<<<<<<<<<<<<<<<<<<<<<<\n");
            print_pktap_header_all_details(pktapHdr, ipData, len);
            printf("classify:)))))))>>>>>>>>>>>>>>>>>>>>>>>>\n");
        }
        /*
        if (strcmp(inet_ntoa(ip4Hdr->ip_dst), "1.1.1.1")==0)
        {
            printf("classify:====>>> 1.1.1.1 OUT...\n");
            print_pktap_header_all_details(pktapHdr, ipData, len);
        }*/
    }
    //print_pktap_header_all_details(pktapHdr, ipData, len);
    // ------------------------------------------------

    // process only outgoing packets
    if ((pktapHdr->pth_flags & PTH_FLAG_DIR_OUT)==0) {
        return 0;
    }
    
    // process only packets from the desired interface
    if (strncmp(IF_vTUN_NAME, pktapHdr->pth_ifname, IFNAMSIZ) != 0) {
        return 0;
    }

    //print_pktap_header(pktapHdr, "   ++++ ");    
    //printf("<<<<<<<<<<<<<<<<<<<<<<<<\n");
    //print_pktap_header_all_details(pktapHdr, ipData, len);
    //printf(">>>>>>>>>>>>>>>>>>>>>>>>\n");

    int ret = injectToDefaultInterface(ipData, len);

    return ret;
}

int injectToDefaultInterface(unsigned char* ipData, unsigned int len) 
{
    int totalLen = sizeof(struct ether_header) + len;
    if (totalLen > sizeof(buffer))
        return -3;

    memset(buffer, 0, totalLen); // TODO: we can skip this memset
    struct ether_header *eth_header = (struct ether_header *)buffer;   
    struct ip *ip_header = (struct ip *)(buffer + sizeof(struct ether_header)); 

    // set source and destination MAC addresses
    memcpy(eth_header->ether_dhost, ROUTER_MAC, ETHER_ADDR_LEN);
    memcpy(eth_header->ether_shost, IF_DEFAULT_MAC, ETHER_ADDR_LEN);
    eth_header->ether_type = htons(ETHERTYPE_IP);

    // copy packet data
    memcpy(ip_header, ipData, len);

    //update the source IP address
    ip_header->ip_src = IF_DEFAULT_IP;

    //update IPv4 checksum
    update_ip_header_checksum(ip_header);

    // Update TCP/UDP checksum
    if (ip_header->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcp_header = (struct tcphdr *)((u_char *)ip_header + ip_header->ip_hl * 4);
        const u_char *payload = (u_char *)tcp_header + sizeof(struct tcphdr);
        int payload_len = ntohs(ip_header->ip_len) - (ip_header->ip_hl * 4) - sizeof(struct tcphdr);
        update_tcp_checksum(ip_header, tcp_header, payload, payload_len);
    } 
    else if (ip_header->ip_p == IPPROTO_UDP)
    {
        struct udphdr *udp_header = (struct udphdr *)((const u_char *)ip_header + ip_header->ip_hl * 4);
        const u_char *payload = (const u_char *)udp_header + sizeof(struct udphdr);
        int payload_len = ntohs(udp_header->uh_ulen) - sizeof(struct udphdr);
        update_udp_checksum(ip_header, udp_header, payload, payload_len);
    }

    // Inject the packet
    int ret = inject_packet(&_handler_inject_if_default, buffer, totalLen);
    if (ret != 0) {
        fprintf(stderr, "Error injecting packet\n");
    } else {
        //printf("Packet injected successfully\n");
    }
    return ret;
}