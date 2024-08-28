#include <netinet/ip.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <stdio.h>

#include "inc/pktap.h"

#include "checksum.c"
#include "print_frame_helpers.c"

#include "do_bpf.h"

#include "config.h"

unsigned char buffer[sizeof(struct ether_header) + 0xFFFF] = {0};

//#define _USE_BPF_
#ifdef _USE_BPF_
    int     handle_default_if_bpf_fd = 0;
#else
    pcap_t *handle_default_if_pcap  = NULL;
#endif

int injectToDefaultInterface(unsigned char* ipData, unsigned int len);

int classify_openForInjection()
{    
#ifdef _USE_BPF_
    if (bpfOpen(IF_DEFAULT_NAME, &handle_default_if_bpf_fd) != 0) {
        fprintf(stderr, "Couldn't open device: %s\n", IF_DEFAULT_NAME);
        return 1;
    }
#else
    char errbuf[PCAP_ERRBUF_SIZE];
    handle_default_if_pcap = pcap_open_live(IF_DEFAULT_NAME, BUFSIZ, 0, 0, errbuf);
    if (handle_default_if_pcap == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return 1;
    }
#endif
    return 0; 
}

int closeForInjection() {
#ifdef _USE_BPF_
    if (handle_default_if_bpf_fd == 0)
        return 0;
    bpfClose(handle_default_if_bpf_fd);
    handle_default_if_bpf_fd = 0;
#else
    if (handle_default_if_pcap == NULL)
        return 0;
    pcap_close(handle_default_if_pcap);
    handle_default_if_pcap = NULL;
#endif
    return 0;
}

int classify_func(const struct pktap_header *pktapHdr, unsigned char* ipData, unsigned int len) 
{
#ifdef _USE_BPF_
    if (handle_default_if_bpf_fd == 0) 
        return -1;
#else
    if (handle_default_if_pcap == NULL) 
        return -1;
#endif

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
    //printf("\n");
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

#ifdef _USE_BPF_
    if (bpfInjectPacket(handle_default_if_bpf_fd, buffer, totalLen) != 0) {
        fprintf(stderr, "Error injecting packet\n");
    } else {
        //printf("Packet injected successfully\n");
    }
#else
    // Inject the packet
    if (pcap_inject(handle_default_if_pcap, buffer, totalLen) == -1) {
        pcap_perror(handle_default_if_pcap, "Error injecting packet");
    } else {
        //printf("Packet injected successfully\n");
    }
#endif
    return 0;
}