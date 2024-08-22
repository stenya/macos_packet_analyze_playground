#include <netinet/ip.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <stdio.h>

#include "inc/pktap.h"

#include "checksum.c"
#include "print_frame_helpers.c"

unsigned char buffer[sizeof(struct ether_header) + 0xFFFF] = {0};

pcap_t *handle = NULL;

unsigned char* _ifMac;
struct in_addr _ifAddr;
unsigned char* _dstIfMac;

char _filter_interface_name[IFNAMSIZ] = {0};

int injectToDefaultInterface(unsigned char* ipData, unsigned int len);

int openForInjection(
    char* if_name_default, 
    unsigned char* if_default_MAC, 
    struct in_addr if_default_Ipv4Addr, 
    unsigned char* route_MAC,
    char *filter_ifname)
{
    _ifMac      = if_default_MAC;
    _ifAddr     = if_default_Ipv4Addr;
    _dstIfMac   = route_MAC;

    strncpy(_filter_interface_name, filter_ifname, IFNAMSIZ);
    //_filter_interface_name = filter_ifname;

    char errbuf[PCAP_ERRBUF_SIZE];
    
    handle = pcap_open_live(if_name_default, BUFSIZ, 1, 1, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return 1;
    }

    return 0; 
}

int closeForInjection() {
    if (handle == NULL)
        return 0;

    pcap_close(handle);
    handle = NULL;

    return 0;
}

int inject_func(const struct pktap_header *pktapHdr, unsigned char* ipData, unsigned int len) 
{
    if (handle == 0 || pktapHdr == NULL || ipData == NULL) 
        return -1;

    // TODO: currently we are using only IPV4. We must support IPv6 also!
    if (len < sizeof(struct ether_header) + sizeof(struct ip))
        return -2;

    // ------------------------------------------------ DEBUG
    struct ip *ip4Hdr   = NULL;
    if (pktapHdr->pth_protocol_family == AF_INET) 
    {
        ip4Hdr   = (struct ip *)ipData;
        //printf("  -Source IP: %s\n", inet_ntoa(ip4Hdr->ip_src));
        //printf("  -Destination IP: %s\n", inet_ntoa(ip4Hdr->ip_dst));
        if (strcmp(inet_ntoa(ip4Hdr->ip_src), "93.184.216.34")==0)
        {
            printf("!===>>>GOT RESPONSE!\n");
            printf("(((((((<<<<<<<<<<<<<<<<<<<<<<<<\n");
            print_pktap_header_all_details(pktapHdr, ipData, len);
            printf(")))))))>>>>>>>>>>>>>>>>>>>>>>>>\n");
        }
    }

    if (strcmp(inet_ntoa(ip4Hdr->ip_dst), "93.184.216.34")==0)
    {
        printf("====>>> sending...\n");
        printf("(((((((<<<<<<<<<<<<<<<<<<<<<<<<\n");
        print_pktap_header_all_details(pktapHdr, ipData, len);
        printf(")))))))>>>>>>>>>>>>>>>>>>>>>>>>\n");
    }
    // ------------------------------------------------


    // process only outgoing packets
    if ((pktapHdr->pth_flags & PTH_FLAG_DIR_OUT)==0) {
        return 0;
    }
    
    // process only packets from the desired interface
    if (strncmp(_filter_interface_name, pktapHdr->pth_ifname, IFNAMSIZ) != 0) {
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
    memcpy(eth_header->ether_dhost, _dstIfMac, ETHER_ADDR_LEN);
    memcpy(eth_header->ether_shost, _ifMac, ETHER_ADDR_LEN);
    eth_header->ether_type = htons(ETHERTYPE_IP);

    // copy packet data
    memcpy(ip_header, ipData, len);

    //update the source IP address
    ip_header->ip_src = _ifAddr;

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

        // Update UDP checksum
        update_udp_checksum(ip_header, udp_header, payload, payload_len);
    }

    // Inject the packet
    if (pcap_inject(handle, buffer, totalLen) == -1) {
        pcap_perror(handle, "Error injecting packet");
    } else {
        //printf("Packet injected successfully\n");
    }

    return 0;
}