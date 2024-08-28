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

int injectToVpnInterface(struct ip *ip_header, int isIn);

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

    if (_debug) // LOGGING (DEBUG)
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

    if (ip4Hdr != NULL && 
    (strcmp(inet_ntoa(ip4Hdr->ip_dst), "1.1.1.1")==0 || strcmp(inet_ntoa(ip4Hdr->ip_src), "1.1.1.1")==0))
    {
        printf("-----\n");
        print_pktap_header(pktapHdr, "PKTAP    ");
        print_ip_4(ip4Hdr, "PKTAP    ");
    }

    if (_pkt_handler!=NULL && ip4Hdr != NULL) 
    {
        /// TEST: INJECT TO VPN
        if ( (pktapHdr->pth_flags & PTH_FLAG_DIR_IN)
                && strcmp(pktapHdr->pth_ifname, "en0")==0 
                && (strcmp(inet_ntoa(ip4Hdr->ip_src), "34.117.59.81")==0 || strcmp(inet_ntoa(ip4Hdr->ip_src), "1.1.1.1")==0)             
            )
        {
            printf("INJECTING TO VPN (IN)...\n");
            if (injectToVpnInterface(ip4Hdr, 1)==0) 
                printf("OK\n");
            else 
                printf("ERROR\n");
                    
            return;
        }

        _pkt_handler(pktapHdr, (unsigned char*)ip4Hdr, ntohs(ip4Hdr->ip_len));
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

#include "checksum.c"
pcap_t *vpnIf_W_Handle = NULL;
struct in_addr vpnIf_Addr;

int pktap_PrepareVPNIfToInjectInFrames(const char* vpnIf, struct in_addr vpnIp ) {
    char errbuf[PCAP_ERRBUF_SIZE];

    vpnIf_Addr = vpnIp;

    vpnIf_W_Handle = pcap_open_live(vpnIf, BUFSIZ, 0, 0, errbuf);
    if (vpnIf_W_Handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return 1;
    }
    return 0;
}

unsigned char _w_buffer[sizeof(struct ether_header) + 0xFFFF] = {0};
int injectToVpnInterface(struct ip *ip4_Header, int isIn) 
{
    if (vpnIf_W_Handle==NULL) return -1;
    
    
    unsigned int ip4FrameLen = ntohs(ip4_Header->ip_len);
    int totalLen = 4 + ip4FrameLen;

    memset(_w_buffer, 0, totalLen); // TODO: we can skip this memset
    _w_buffer[0]=2; // TODO: MAGIC!!! Investigate ))) "02 00 00 00" - on the begining
    struct ip *ip4Hdr = (struct ip *)&_w_buffer[4];
    memcpy(ip4Hdr, ip4_Header, ip4FrameLen);

    if (isIn) {    
        ip4Hdr->ip_dst = vpnIf_Addr;
    } else {
        /*
        struct in_addr ipTun;
        if (inet_aton("10.88.88.89", &ipTun) == 0) {
            printf("Invalid IP address format\n");
            return -1;
        }
        ip4Hdr->ip_src = ipTun;*/

        ip4Hdr->ip_src = vpnIf_Addr;
    }
    
    //update IPv4 checksum
    update_ip_header_checksum(ip4Hdr);

    // Update TCP/UDP checksum
    if (ip4Hdr->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcp_header = (struct tcphdr *)((u_char *)ip4Hdr + ip4Hdr->ip_hl * 4);
        const u_char *payload = (u_char *)tcp_header + sizeof(struct tcphdr);
        int payload_len = ntohs(ip4Hdr->ip_len) - (ip4Hdr->ip_hl * 4) - sizeof(struct tcphdr);
        update_tcp_checksum(ip4Hdr, tcp_header, payload, payload_len);

        print_ip_4(ip4Hdr, "   NEW: ");
        print_tcphdr(tcp_header, "   NEW: ");
    } 
    else if (ip4Hdr->ip_p == IPPROTO_UDP)
    {
        struct udphdr *udp_header = (struct udphdr *)((const u_char *)ip4Hdr + ip4Hdr->ip_hl * 4);
        const u_char *payload = (const u_char *)udp_header + sizeof(struct udphdr);
        int payload_len = ntohs(udp_header->uh_ulen) - sizeof(struct udphdr);

        // Update UDP checksum
        update_udp_checksum(ip4Hdr, udp_header, payload, payload_len);
    }
    
    // Inject the packet
    if (pcap_inject(vpnIf_W_Handle, _w_buffer, totalLen) == -1) {
        pcap_perror(vpnIf_W_Handle, "Error injecting packet");
        return -2;
    } else {
        //printf("Packet injected successfully\n");
    }

    return 0;
}