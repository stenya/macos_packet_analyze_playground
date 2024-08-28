#include <netinet/ip.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <stdio.h>

#include "inc/pktap.h"

#include "checksum.c"
#include "print_frame_helpers.c"

#include "bpf.h"

#include "config.h"

#include "inject.c"

// Possible types of injection handlers: INJECT_TYPE_PCAP, INJECT_TYPE_BPF
int                     _hdlr_inject_IF_DEF_type       = INJECT_TYPE_BPF;
struct inject_handler   _hdlr_inject_IF_DEF;

int                     _hdlr_inject_IF_VPN_type       = INJECT_TYPE_PCAP;
struct inject_handler   _hdlr_inject_IF_VPN;

int do_inject(struct ip* orig_ip4Hdr, 
        const struct in_addr* srcIP,  const struct in_addr* dstIP,
        const unsigned char*  srcMAC, const unsigned char*  dstMAC, 
        struct inject_handler *handler)  ;

int classify_openForInjection()
{    
    const char*  OUT_IF_NAME = IF_DEFAULT_NAME;
    const char*  IN_IF_NAME  = IF_vTUN_NAME;

    // Open the default interface for injection
    printf("Opening for OUT injection '%s'...\n", OUT_IF_NAME);
    if (inject_open(_hdlr_inject_IF_DEF_type, OUT_IF_NAME, &_hdlr_inject_IF_DEF) != 0) {
        fprintf(stderr, "Couldn't open device: %s\n", OUT_IF_NAME);
        return -1;
    }
    printf("'%s' opened for injection\n", OUT_IF_NAME);

    // Open the VPN interface for injection
    printf("Opening for IN injection '%s'...\n", IN_IF_NAME);
    if (inject_open(_hdlr_inject_IF_VPN_type, IN_IF_NAME, &_hdlr_inject_IF_VPN) != 0) {
        fprintf(stderr, "Couldn't open device: %s\n", IF_vTUN_NAME);
        return -1;
    }
    printf("'%s' opened for injection\n", IN_IF_NAME);

    return 0;
}

int closeForInjection() {
    if (inject_close(&_hdlr_inject_IF_DEF) != 0) {
        fprintf(stderr, "Error closing injection handler\n");        
    }
    if (inject_close(&_hdlr_inject_IF_VPN) != 0) {
        fprintf(stderr, "Error closing injection handler\n");        
    }
    return 0;
}

int classify_func(const struct pktap_header *pktapHdr, struct ip* ip4Hdr) 
{
    if (pktapHdr == NULL || ip4Hdr == NULL) 
        return -1;

    // ------------------------------------------------ DEBUG
    if (pktapHdr->pth_protocol_family == AF_INET) 
    {        
        if (strcmp(inet_ntoa(ip4Hdr->ip_src), "93.184.216.34")==0)
        {
            printf("classify: !===>>>GOT RESPONSE!\n");
            printf("classify:(((((((<<<<<<<<<<<<<<<<<<<<<<<<\n");
            print_pktap_header_all_details(pktapHdr, (unsigned char*) ip4Hdr, ntohs(ip4Hdr->ip_len));
            printf("classify:)))))))>>>>>>>>>>>>>>>>>>>>>>>>\n");
        }    
        if (strcmp(inet_ntoa(ip4Hdr->ip_dst), "93.184.216.34")==0)
        {
            printf("classify:====>>> sending...\n");
            printf("classify:(((((((<<<<<<<<<<<<<<<<<<<<<<<<\n");
            print_pktap_header_all_details(pktapHdr, (unsigned char*) ip4Hdr, ntohs(ip4Hdr->ip_len));
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

    // <<<<<<<<< INJECT TO VPN REPLIES (IN)
    if ( (pktapHdr->pth_flags & PTH_FLAG_DIR_IN)
                && strcmp(pktapHdr->pth_ifname, "en0")==0 
                && (strcmp(inet_ntoa(ip4Hdr->ip_src), "34.117.59.81")==0 || strcmp(inet_ntoa(ip4Hdr->ip_src), "1.1.1.1")==0)             
            )
    {
        printf("INJECTING TO VPN (IN)...\n");
        int ret = do_inject(ip4Hdr, NULL, &IF_VPN_IP, NULL, NULL, &_hdlr_inject_IF_VPN);
        if (ret==0) printf("OK\n");
        else printf("ERROR\n");                    
        return ret;
    }
    // >>>>>>>>> //INJECT TO VPN

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

    // INJECT TO DEFAULT INTERFACE
    int ret = do_inject(
        ip4Hdr, 
        &IF_DEFAULT_IP, NULL, 
        IF_DEFAULT_MAC, ROUTER_MAC,
        &_hdlr_inject_IF_DEF);

    return ret;
}


unsigned char buffer[sizeof(struct ether_header) + 0xFFFF] = {0};
int do_inject(struct ip* orig_ip4Hdr, 
        const struct in_addr* srcIP,  const struct in_addr* dstIP,
        const unsigned char*  srcMAC, const unsigned char*  dstMAC, 
        struct inject_handler *handler) 
{
    int ip4FrameLen     = ntohs(orig_ip4Hdr->ip_len);
    int totalLen        = 0;
    struct ip *ip4Hdr   = NULL;

    if (srcMAC != NULL && dstMAC != NULL) {        
        // MAC addresses are defined
        totalLen = sizeof(struct ether_header) + ip4FrameLen;
        if (totalLen > sizeof(buffer))
            return -3;

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
            return -3;

        //memset(buffer, 0, totalLen);    // TODO: we can skip this memset
        buffer[0]=2;                    // TODO: MAGIC!!! Investigate ))) "02 00 00 00" - on the begining
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

    // Inject the packet
    int ret = inject_packet(handler, buffer, totalLen);
    if (ret != 0) 
        fprintf(stderr, "Error injecting packet\n");
    return ret;
}