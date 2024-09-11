#include <netinet/ip.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <stdio.h>

#include "inc/pktap.h"

#include "checksum.c"
#include "print_frame_helpers.c"

#include "bpf.h"

#include "config.h"
#include "tun.h"

int                     _hdlr_DEF_bpf           = -1; // for OUT:VPN->vTUN->DEF and IN:DEF-> (VPN/vTUN ???) 
int                     _hdlr_VPN_injectOUT_bpf = -1; // for OUT:VPN->vTUN->VPN

struct tun_handler      _virtualTunIf; // Virtual TUN interface (created). 

unsigned char*  prepare_data_to_inject(
        size_t* out_buffer_len,
        struct ip* orig_ip4Hdr, 
        const struct in_addr* srcIP,  const struct in_addr* dstIP,
        const unsigned char*  srcMAC, const unsigned char*  dstMAC);

void onIncomingPacketOnDefaultIf(unsigned char* ip4_header) {
    struct ip* ip4Hdr = (struct ip*)ip4_header;
        
    //
    // Forward all incoming packets from default interface to VirtualTunnel 
    // TODO: SKIP IP ADDRESS OF VPN SERVER ???
    //

    // TEST: SKIP IP ADDRESS OF VPN SERVER ???
    if (strcmp(inet_ntoa(ip4Hdr->ip_src), VPN_SERVER_IP_STR)==0 )
        return;

    print_ip_4(ip4Hdr, "IN (def) = ");

    //*
    size_t totalLen;
    unsigned char* buff = prepare_data_to_inject(&totalLen, ip4Hdr, NULL, &IF_VPN_IP, NULL, NULL);
    if (buff == NULL || totalLen <= 4 + sizeof(struct ip)) {
        fprintf(stderr, "Error preparing data to inject UTUN\n");
        return;
    }

    print_ip_4((const struct ip *)&buff[4], "           ---> ");

    ssize_t sent = tun_write(&_virtualTunIf, buff, totalLen);
    if (sent != totalLen) {
        fprintf(stderr, "Error injecting to UTUN\n");
        return;
    }
    //*/

    /*
    // TEST <<<<<
    // Forward all incoming data (on default interface) to VPN interface
    size_t totalLen;
    unsigned char* buff = prepare_data_to_inject(&totalLen, ip4Hdr, NULL, &IF_VPN_IP, NULL, NULL);
    if (buff == NULL || totalLen <= 4 + sizeof(struct ip)) {
        fprintf(stderr, "Error preparing data to inject UTUN\n");
        return;
    }
    ssize_t sent = bpfWrite(_hdlr_VPN_injectOUT_bpf, buff, totalLen);
    if (sent != totalLen) {
        perror("Error injecting to VPN\n");
        return;
    }
    // TEST >>>>>
    //*/
}

int classify_INIT()
{    
    const char*  OUT_IF_NAME = IF_DEFAULT_NAME;
    
    //
    // Create Virtual TUN
    //
    memset(&_virtualTunIf, 0, sizeof(struct tun_handler));
    _virtualTunIf.cfg_ip = (char*)IF_VTUN_IP_STR;
    _virtualTunIf.cfg_dst_ptp_ip = (char*)IF_VTUN_PTP_IP_STR;
    _virtualTunIf.cfg_subnet_mask = (char*)IF_VTUN_MASK_STR;

    if (tun_thread_run(&_virtualTunIf)!=0) {
        fprintf(stderr, "Error opening TUN interface\n");
        return -1;
    }
    printf("TUN interface opened: %s\n", _virtualTunIf.ifname);

    //
    // Open the default interface
    //    
    printf("Opening default interface '%s'...\n", OUT_IF_NAME);
    if (bpfOpen(OUT_IF_NAME, &_hdlr_DEF_bpf, onIncomingPacketOnDefaultIf, 0) != 0) {
        fprintf(stderr, "Couldn't open device: %s\n", OUT_IF_NAME);
        return -1;
    }
    printf("'%s' opened\n", OUT_IF_NAME);

    //
    // Print message and wait for Enter
    printf("PAUSE. Connect VPN and press Enter to continue...\n");
    //getchar();
    //

    //
    // Open VPN interface for injection OUT packets
    //
    if (bpfOpen(IF_VPN_NAME, &_hdlr_VPN_injectOUT_bpf, NULL, 1)!=0) {
        fprintf(stderr, "Error opening BPF device for VPN\n");
        return -1;
    }

    return 0;
}

int classify_STOP() {
    if (tun_thread_stop(&_virtualTunIf) != 0) {
        fprintf(stderr, "Error closing TUN interface (%s)\n", _virtualTunIf.ifname);        
    }
    bpfClose(_hdlr_DEF_bpf);
    bpfClose(_hdlr_VPN_injectOUT_bpf);    
    return 0;
}

// Received PKTAP packet
int on_PKTAP_packet(const struct pktap_header *pktapHdr, struct ip* ip4Hdr) 
{
    if (pktapHdr == NULL || ip4Hdr == NULL) 
        return -1;

    //printf("<<<<<<<<<<<<<<<<<<<<<<<<\n");
    //print_pktap_header_all_details(pktapHdr, (unsigned char*) ip4Hdr, ntohs(ip4Hdr->ip_len));
    //printf(">>>>>>>>>>>>>>>>>>>>>>>>\n");

    // process only outgoing packets
    if ((pktapHdr->pth_flags & PTH_FLAG_DIR_OUT)==0) {
        return 0;
    }
    
    // process only packets from the desired interface
    if (strncmp(_virtualTunIf.ifname, pktapHdr->pth_ifname, IFNAMSIZ) != 0) {
        return 0;
    }

    int DO_SPLIT = 0;

    //
    // TEST: 
    // Connection to "34.117.59.81" and "1.1.1.1" send over default interface
    //
    DO_SPLIT = strcmp(inet_ntoa(ip4Hdr->ip_dst), "34.117.59.81")==0 || strcmp(inet_ntoa(ip4Hdr->ip_dst), "1.1.1.1")==0;

    if (DO_SPLIT) {
        size_t totalLen;
        unsigned char* buff = prepare_data_to_inject(&totalLen, ip4Hdr, 
            &IF_DEFAULT_IP, NULL, 
            IF_DEFAULT_MAC, ROUTER_MAC);

        if (buff == NULL || totalLen <= 4 + sizeof(struct ip)) {
            perror("Error preparing data to inject UTUN\n");
            return -1;
        }        
        ssize_t sent = bpfWrite(_hdlr_DEF_bpf, buff, totalLen);
        if (sent != totalLen) {
            perror("Error injecting to UTUN\n");
            return -1;
        }
        return 0;
    }
    
    //
    // Inject OUT frame back to VPN interface
    //
    ssize_t sent = bpfWrite(_hdlr_VPN_injectOUT_bpf, ip4Hdr, ntohs(ip4Hdr->ip_len));
    if (sent != ntohs(ip4Hdr->ip_len)) {
        perror("Error injecting to VPN\n");
        return -1;
    }
   
    return 0;
}


unsigned char buffer[sizeof(struct ether_header) + 0xFFFF] = {0};
unsigned char*  prepare_data_to_inject(
        size_t* out_buffer_len,
        struct ip* orig_ip4Hdr, 
        const struct in_addr* srcIP,  const struct in_addr* dstIP,
        const unsigned char*  srcMAC, const unsigned char*  dstMAC) 
{    
    *out_buffer_len     = 0;

    int ip4FrameLen     = ntohs(orig_ip4Hdr->ip_len);
    int totalLen        = 0;
    struct ip *ip4Hdr   = NULL;

    if (srcMAC != NULL && dstMAC != NULL) {        
        // MAC addresses are defined
        totalLen = sizeof(struct ether_header) + ip4FrameLen;
        if (totalLen > sizeof(buffer))
            return NULL;

        //memset(buffer, 0, totalLen);    // TODO: we can skip this memset
        struct ether_header *eth_header = (struct ether_header *)buffer;   
        ip4Hdr = (struct ip *)(buffer + sizeof(struct ether_header)); 

        // set source and destination MAC addresses
        memcpy(eth_header->ether_shost, srcMAC, ETHER_ADDR_LEN);
        memcpy(eth_header->ether_dhost, dstMAC, ETHER_ADDR_LEN);    
        eth_header->ether_type = htons(ETHERTYPE_IP);
    } else {
        // MAC addresses are NOT defined
        totalLen = 4 + ip4FrameLen;     // "02 00 00 00" + orig_ip4Hdr
        if (totalLen > sizeof(buffer))
            return NULL;

        //memset(buffer, 0, totalLen);    // TODO: we can skip this memset
        buffer[0]=2;                    // TODO: MAGIC symbols equivalent to AF_INET ("02 00 00 00" - on the begining)
        buffer[1]=0;
        buffer[2]=0;
        buffer[3]=0;
        ip4Hdr = (struct ip *)&buffer[4];
    }

    // copy packet data
    memcpy(ip4Hdr, orig_ip4Hdr, ip4FrameLen);

    //update IP address
    if (srcIP != NULL)
        ip4Hdr->ip_src = *srcIP;
    if (dstIP != NULL)
        ip4Hdr->ip_dst = *dstIP;

    //update IPv4 checksum
    update_ip_header_checksum(ip4Hdr);

    // Update TCP/UDP checksum
    if (ip4Hdr->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcp_header = (struct tcphdr *)((u_char *)ip4Hdr + ip4Hdr->ip_hl * 4);
        const u_char *payload = (u_char *)tcp_header + sizeof(struct tcphdr);
        int payload_len = ntohs(ip4Hdr->ip_len) - (ip4Hdr->ip_hl * 4) - sizeof(struct tcphdr);
        update_tcp_checksum(ip4Hdr, tcp_header, payload, payload_len);
    } 
    else if (ip4Hdr->ip_p == IPPROTO_UDP)
    {
        struct udphdr *udp_header = (struct udphdr *)((const u_char *)ip4Hdr + ip4Hdr->ip_hl * 4);
        const u_char *payload = (const u_char *)udp_header + sizeof(struct udphdr);
        int payload_len = ntohs(udp_header->uh_ulen) - sizeof(struct udphdr);
        update_udp_checksum(ip4Hdr, udp_header, payload, payload_len);
    }
    
    *out_buffer_len = totalLen;
    return buffer;
}