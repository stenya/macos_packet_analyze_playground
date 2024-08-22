#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include <sys/param.h>
#include "inc/pktap.h"

#include <net/ethernet.h>

#define PRIVATE 1       // required to enable definition of 'pcap_set_want_pktap(pcap_t *, int);' in pcap.h
#include "inc/pcap.h"

#include "print_frame_helpers.c"

typedef int pkt_handle_func(const struct pktap_header *pktapHdr, unsigned char* data, unsigned int len);

pkt_handle_func*    _pkt_handler    = NULL;

int                 _debug          = 0;

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

    if (_debug )
    {
        print_pktap_header(pktapHdr, "***");
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
        print_ether_header((struct ether_header *)data, "   ");
    }

    const struct tcphdr *tcpHdr = NULL;
    const struct udphdr *udpHdr = NULL;

    const struct ip *ipHdr   = NULL;

    if (pktapHdr->pth_protocol_family == AF_INET) {
        // IPv4 header
        ipHdr   = (const struct ip *)&data[pktapHdr->pth_frame_pre_length];
        if (_debug && ipHdr!=NULL) 
        {
            if (ipHdr->ip_p == IPPROTO_TCP) 
                tcpHdr = (const struct tcphdr *)((const u_char *)ipHdr + ipHdr->ip_hl * 4);
            else if (ipHdr->ip_p == IPPROTO_UDP)
                udpHdr = (const struct udphdr *)((const u_char *)ipHdr + ipHdr->ip_hl * 4);

            if (_debug) 
            {
                print_ip_4(ipHdr, "   ");
            }
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
                print_ip_6(ip6Hdr, "   ");
            }
        }
    }
    else
    {
        if (_debug)
            printf("!!! NOT IPv4 or IPv6 <protocol family=%d>!!! \n", pktapHdr->pth_protocol_family);
    }

    if (_debug)
    {
        if (tcpHdr!=NULL)       print_tcphdr(tcpHdr, "   ");
        else if (udpHdr!=NULL)  print_udphdr(udpHdr, "   ");
    }

    if (_pkt_handler!=NULL && ipHdr != NULL) {
            _pkt_handler(pktapHdr, (unsigned char*)ipHdr, ntohs(ipHdr->ip_len));
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
     
    if ( pcap_set_immediate_mode(pkap, 1) != 0) { // ???
        fprintf(stderr, "Error setting immediate mode\n");
        pcap_close(pkap);
        return -1;
    }  
  
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