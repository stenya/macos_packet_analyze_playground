#include <netinet/ip.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <stdio.h>

#include "inc/pktap.h"

unsigned char buffer[1024*10] = {0};

pcap_t *handle = NULL;

unsigned char* _ifMac;
struct in_addr _ifAddr;
unsigned char* _dstIfMac;

char _filter_interface_name[IFNAMSIZ] = {0};


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

    if (len < sizeof(struct ether_header) + sizeof(struct ip))
        return -2;

    int totalLen = sizeof(struct ether_header) + len;
    if (totalLen > sizeof(buffer))
        return -3;

    memset(buffer, 0, totalLen); // TODO: we can skip this memset

    struct ether_header *eth_header = (struct ether_header *)buffer;
    struct ip *ip_header = (struct ip *)(buffer + sizeof(struct ether_header));
    
    // process only packets from the desired interface
    if (strncmp(_filter_interface_name, pktapHdr->pth_ifname, IFNAMSIZ) != 0) {
        return 0;
    }

    // ------------------------------------------------ DEBUG
    struct ip *ip4Hdr   = NULL;
    if (pktapHdr->pth_protocol_family == AF_INET) 
    {
        ip4Hdr   = (const struct ip *)ipData;
        printf("  -Source IP: %s\n", inet_ntoa(ip4Hdr->ip_src));
        printf("  -Destination IP: %s\n", inet_ntoa(ip4Hdr->ip_dst));
    }
    // ------------------------------------------------

    // process only outgoing packets
    if ((pktapHdr->pth_flags & PTH_FLAG_DIR_OUT) == 0) {        
        return 0;
    }

     printf("+++ %s | ipproto: %02d | family: %02d | next: %d | dev: %s | pid: %04d | proc: %s \n", 
            ((pktapHdr->pth_flags&PTH_FLAG_DIR_OUT)>0)?" IN" : "OUT",          
            pktapHdr->pth_ipproto, 
            pktapHdr->pth_protocol_family,
            pktapHdr->pth_type_next,
            pktapHdr->pth_ifname,
            pktapHdr->pth_pid, 
            pktapHdr->pth_comm);


    // set source and destination MAC addresses
    memcpy(eth_header->ether_dhost, _dstIfMac, ETHER_ADDR_LEN);
    memcpy(eth_header->ether_shost, _ifMac, ETHER_ADDR_LEN);
    eth_header->ether_type = htons(ETHERTYPE_IP);

    // copy packet data
    memcpy(ip_header, ipData, len);

    TODO: update the source IP address
    TODO: update checksum

    /*
    // THIS IS JUST TEST
    struct in_addr desiredIP;
    if (inet_aton("1.1.1.1", &desiredIP) == 0) {
        printf("Invalid IP address format\n");
        return -3;
    }
    if (memcmp(&ip_header->ip_dst, &desiredIP, sizeof(desiredIP)) != 0) 
    {
        return -4;
    }
    buffer[totalLen-1] = 'X';
    */

        // Inject the packet
    if (pcap_inject(handle, buffer, totalLen) == -1) {
        pcap_perror(handle, "Error injecting packet");
    } else {
        printf("Packet injected successfully\n");
    }

    return 0;
}