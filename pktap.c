#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>

#include <sys/param.h>
#include "inc/pktap.h"

#include <net/ethernet.h>

#define PRIVATE 1       // required to enable definition of 'pcap_set_want_pktap(pcap_t *, int);' in pcap.h
#include "inc/pcap.h"

// Packet handler function
void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    
    if  (pkthdr->len != pkthdr->caplen) {
        printf("ERROR! pkthdr->len != pkthdr->caplen\n");
        return;
    }
    if (pkthdr->len < sizeof(struct pktap_header)) {
        printf("ERROR!  Invalid pktap header length\n");
        return;
    }

    // PKTAP HEADER
    struct pktap_header *pktapHdr = (struct pktap_header *) packet;
    printf("*** %s | pid: %04d | ipproto: %02d | family: %02d | dev: %s \n", 
        ((pktapHdr->pth_flags&PTH_FLAG_DIR_OUT)>0)?" IN" : "OUT",  
        pktapHdr->pth_pid, 
        pktapHdr->pth_ipproto, 
        pktapHdr->pth_protocol_family,
        pktapHdr->pth_ifname );
    
    const u_char* data = NULL;
    if  (pkthdr->len > pktapHdr->pth_length) {
        data = &packet[pktapHdr->pth_length];
    }
    if (data==NULL) 
    {
        printf("No data\n");
        return;
    }

    // Ethernet header
    struct ether_header *eth_header = (struct ether_header *)data;
    printf(" Ethernet Header (type=%d): \n", ntohs(eth_header->ether_type));
    printf("\tSource MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_header->ether_shost[0], eth_header->ether_shost[1],
           eth_header->ether_shost[2], eth_header->ether_shost[3],
           eth_header->ether_shost[4], eth_header->ether_shost[5]);
    printf("\tDestination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_header->ether_dhost[0], eth_header->ether_dhost[1],
           eth_header->ether_dhost[2], eth_header->ether_dhost[3],
           eth_header->ether_dhost[4], eth_header->ether_dhost[5]);


    if (pktapHdr->pth_protocol_family == AF_INET) {
        // IPv4 header
        const struct ip *ipHdr   = (const struct ip *)&data[sizeof(struct ether_header)];
        if (ipHdr!=NULL) 
        {
            printf("  Version: %d\n", ipHdr->ip_v);
            printf("  Header Length: %d (bytes)\n", ipHdr->ip_hl * 4);
            printf("  Type of Service: %d\n", ipHdr->ip_tos);
            printf("  Total Length: %d\n", ntohs(ipHdr->ip_len));
            printf("  Identification: %d\n", ntohs(ipHdr->ip_id));
            printf("  Flags and Fragment Offset: %d\n", ntohs(ipHdr->ip_off));
            printf("  Time to Live: %d\n", ipHdr->ip_ttl);
            printf("  Protocol: %d\n", ipHdr->ip_p);
            printf("  Header Checksum: %d\n", ntohs(ipHdr->ip_sum));
            printf("  Source IP: %s\n", inet_ntoa(ipHdr->ip_src));
            printf("  Destination IP: %s\n", inet_ntoa(ipHdr->ip_dst));
        }
    } 
    else if (pktapHdr->pth_protocol_family == AF_INET6)
    {
        // IPv6 header
        const struct ip6_hdr *ip6Hdr = (const struct ip6_hdr *)&data[sizeof(struct ether_header)];
        if (ip6Hdr!=NULL) 
        {
            char src_ip[INET6_ADDRSTRLEN];
            char dst_ip[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &(ip6Hdr->ip6_src), src_ip, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &(ip6Hdr->ip6_dst), dst_ip, INET6_ADDRSTRLEN);
            printf("  Version: %d\n", ip6Hdr->ip6_vfc);
            printf("  Traffic Class: %d\n", ip6Hdr->ip6_flow);
            printf("  Flow Label: %d\n", ip6Hdr->ip6_flow);
            printf("  Payload Length: %d\n", ntohs(ip6Hdr->ip6_plen));
            printf("  Next Header: %d\n", ip6Hdr->ip6_nxt);
            printf("  Hop Limit: %d\n", ip6Hdr->ip6_hlim);
            printf("  Source IP: %s\n", src_ip);
            printf("  Destination IP: %s\n", dst_ip);
        }
    }
    else
    {
        printf("NOT IPv4 or IPv6\n");
    }

    return; 
}

int DoPktap() {

    char errBuff[PCAP_ERRBUF_SIZE];
    pcap_t * pkap = pcap_create("pktap", errBuff);
    if (pkap == NULL) {
        fprintf(stderr, "Error creating packet tap\n");
        return -1;
    }

    int ret = pcap_set_want_pktap(pkap, 1);
    printf("pcap_set_want_pktap=%d\n", ret);
     
  
    if (pcap_activate(pkap) == -1) {
        fprintf(stderr, "Error activating packet tap\n");
        pcap_close(pkap);
        return -1;
    }

    if ( pcap_setnonblock(pkap, 1, errBuff) != 0) {
        fprintf(stderr, "Error setting non-blocking mode\n");
        pcap_close(pkap);
        return -1;
    }


     // Set the filter to capture packets from utun4
    /*
    struct bpf_program fp;
    char filter_exp[64];
    snprintf(filter_exp, sizeof(filter_exp), "pktap.ifname == %s", "utun4");
    if (pcap_compile(pkap, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(pkap));
        pcap_close(pkap);
        return -1;
    }
    if (pcap_setfilter(pkap, &fp) == -1) {
        fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(pkap));
        pcap_freecode(&fp);
        pcap_close(pkap);
        return -1;
    }
    pcap_freecode(&fp);*/

    // Start the packet capture loop
    pcap_loop(pkap, 0, packet_handler, NULL);

    // Close the capture handle
    pcap_close(pkap);

    return 0;
}