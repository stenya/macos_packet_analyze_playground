#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>

#include <sys/param.h>
#include "inc/pktap.h"

#include <net/ethernet.h>

#define PRIVATE 1       // required to enable definition of 'pcap_set_want_pktap(pcap_t *, int);' in pcap.h
#include "inc/pcap.h"

typedef int pkt_handle_func(const struct pktap_header *pktapHdr, unsigned char* data, unsigned int len);

pkt_handle_func*    _pkt_handler    = NULL;

int                 _debug          = 1;

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

    //if (_ifNameToFilter!=NULL && strcmp(pktapHdr->pth_ifname, _ifNameToFilter) != 0) { // e.g. "utun4"
    //    return;
    //}

    if (_debug )
    {
        printf("*** %s | ipproto: %02d | family: %02d | next: %d | dev: %s | pid: %04d | proc: %s \n", 
            ((pktapHdr->pth_flags&PTH_FLAG_DIR_OUT)>0)?" IN" : "OUT",          
            pktapHdr->pth_ipproto, 
            pktapHdr->pth_protocol_family,
            pktapHdr->pth_type_next,
            pktapHdr->pth_ifname,
            pktapHdr->pth_pid, 
            pktapHdr->pth_comm);
    }
    
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
    // THIS IS JUST FOR TESTS (not for use in produxtion): 
    // if offset equals ether_header size - we read this data as ether_header
    if (_debug && pktapHdr->pth_frame_pre_length == sizeof(struct ether_header))  
    {        
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
    }

    const struct tcphdr *tcpHdr = NULL;
    const struct udphdr *udpHdr = NULL;

    if (pktapHdr->pth_protocol_family == AF_INET) {
        // IPv4 header
        const struct ip *ipHdr   = (const struct ip *)&data[pktapHdr->pth_frame_pre_length];
        if (_debug && ipHdr!=NULL) 
        {
            if (ipHdr->ip_p == IPPROTO_TCP) 
                tcpHdr = (const struct tcphdr *)((const u_char *)ipHdr + ipHdr->ip_hl * 4);
            else if (ipHdr->ip_p == IPPROTO_UDP)
                udpHdr = (const struct udphdr *)((const u_char *)ipHdr + ipHdr->ip_hl * 4);

            if (_debug) 
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

        if (_pkt_handler!=NULL) {
            _pkt_handler(pktapHdr, (unsigned char*)ipHdr, ntohs(ipHdr->ip_len));
        }
    } 
    else if (pktapHdr->pth_protocol_family == AF_INET6)
    {
        // IPv6 header
        const struct ip6_hdr *ip6Hdr = (const struct ip6_hdr *)&data[pktapHdr->pth_frame_pre_length];
        if (ip6Hdr!=NULL) 
        {
            if (ip6Hdr->ip6_nxt == IPPROTO_TCP) 
                tcpHdr = (const struct tcphdr *)((const u_char *)ip6Hdr + sizeof(struct ip6_hdr));
            else if (ip6Hdr->ip6_nxt == IPPROTO_UDP)
                udpHdr = (const struct udphdr *)((const u_char *)ip6Hdr + sizeof(struct ip6_hdr));

            if (_debug) 
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
    }
    else
    {
        printf("NOT IPv4 or IPv6\n");
    }

    if (_debug)
    {
        if (tcpHdr!=NULL) {
            printf("  TCP Header: \n");
            printf("    Source Port: %d\n", ntohs(tcpHdr->th_sport));
            printf("    Destination Port: %d\n", ntohs(tcpHdr->th_dport));
            printf("    Sequence Number: %u\n", ntohl(tcpHdr->th_seq));
            printf("    Acknowledgment Number: %u\n", ntohl(tcpHdr->th_ack));
            printf("    Data Offset: %d (bytes)\n", tcpHdr->th_off * 4);
            printf("    Flags: %d\n", tcpHdr->th_flags);
            printf("    Window: %d\n", ntohs(tcpHdr->th_win));
            printf("    Checksum: %d\n", ntohs(tcpHdr->th_sum));
            printf("    Urgent Pointer: %d\n", ntohs(tcpHdr->th_urp));
        }
        else if (udpHdr!=NULL) {
            printf("  UDP Header: \n");
            printf("    Source Port: %d\n", ntohs(udpHdr->uh_sport));
            printf("    Destination Port: %d\n", ntohs(udpHdr->uh_dport));
            printf("    Length: %d\n", ntohs(udpHdr->uh_ulen));
            printf("    Checksum: %d\n", ntohs(udpHdr->uh_sum));
        }
    }

    return; 
}



int DoPktap(pkt_handle_func *hdlr) {
    _pkt_handler    = hdlr;

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

    // Start the packet capture loop
    pcap_loop(pkap, 0, packet_handler, NULL);

    // Close the capture handle
    pcap_close(pkap);

    return 0;
}