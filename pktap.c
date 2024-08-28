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

typedef int pkt_handle_func(const struct pktap_header *pktapHdr, struct ip* ip4Hdr);
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

    if (_debug) 
        print_pktap_header(pktapHdr, "***");
    
    const u_char* data = NULL;
    if  (pkthdr->len > pktapHdr->pth_length) 
        data = &packet[pktapHdr->pth_length];    

    if (data==NULL) 
    {
        printf("No data\n");
        return;
    }

    // Ethernet header 
    // THIS IS JUST FOR TESTS (not for use in produxtion): 
    // if offset equals ether_header size - we read this data as ether_header
    if (_debug && pktapHdr->pth_frame_pre_length == sizeof(struct ether_header))      
        print_ether_header((struct ether_header *)data, "   ");

    struct ip *ip4Hdr   = NULL;
    struct ip6_hdr *ip6Hdr = NULL;

    if (pktapHdr->pth_protocol_family == AF_INET)
        ip4Hdr   = (struct ip *)&data[pktapHdr->pth_frame_pre_length];
    else if (pktapHdr->pth_protocol_family == AF_INET6)
        ip6Hdr = (struct ip6_hdr *)&data[pktapHdr->pth_frame_pre_length];    

    // <<<<<<< LOGGING (DEBUG)
    if (_debug) 
    {        
        const struct tcphdr *tcpHdr = NULL;
        const struct udphdr *udpHdr = NULL;
        if (ip4Hdr!=NULL)       
        {
            print_ip_4(ip4Hdr, "   ");
            if (ip4Hdr->ip_p == IPPROTO_TCP)            tcpHdr = (const struct tcphdr *)((const u_char *)ip4Hdr + ip4Hdr->ip_hl * 4);
            else if (ip4Hdr->ip_p == IPPROTO_UDP)       udpHdr = (const struct udphdr *)((const u_char *)ip4Hdr + ip4Hdr->ip_hl * 4);
        }
        else if (ip6Hdr!=NULL)  
        {
            print_ip_6(ip6Hdr, "   ");
            if (ip6Hdr->ip6_nxt == IPPROTO_TCP)         tcpHdr = (const struct tcphdr *)((const u_char *)ip6Hdr + sizeof(struct ip6_hdr));
            else if (ip6Hdr->ip6_nxt == IPPROTO_UDP)    udpHdr = (const struct udphdr *)((const u_char *)ip6Hdr + sizeof(struct ip6_hdr));
        }
        else
            printf("!!! NOT IPv4 or IPv6 <protocol family=%d>!!! \n", pktapHdr->pth_protocol_family);
        if (tcpHdr!=NULL)       print_tcphdr(tcpHdr, "   ");
        else if (udpHdr!=NULL)  print_udphdr(udpHdr, "   ");
    }
    // >>>>>>> //LOGGING (DEBUG)

    if (_pkt_handler!=NULL && ip4Hdr != NULL) 
    {
        _pkt_handler(pktapHdr, ip4Hdr);
    }

    return; 
}

int do_pktap_read_vTun(pkt_handle_func *hdlr) {
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