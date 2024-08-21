#include <netinet/ip.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <stdio.h>

#include "inc/pktap.h"

unsigned char buffer[sizeof(struct ether_header) + 0xFFFF] = {0};

pcap_t *handle = NULL;

unsigned char* _ifMac;
struct in_addr _ifAddr;
unsigned char* _dstIfMac;

char _filter_interface_name[IFNAMSIZ] = {0};

void update_ip_header_checksum(struct ip *ip_header);
void update_tcp_checksum(struct ip *ip_header, struct tcphdr *tcp_header, const u_char *payload, int payload_len);
void update_udp_checksum(struct ip *ip_header, struct udphdr *udp_header, const u_char *payload, int payload_len);

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

    // TODO: currently we are using only IPV4. We must support IPv6 also!
    struct ip *ip_header = (struct ip *)(buffer + sizeof(struct ether_header)); 
    
    // process only packets from the desired interface
    if (strncmp(_filter_interface_name, pktapHdr->pth_ifname, IFNAMSIZ) != 0) {
        return 0;
    }

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
        printf("Packet injected successfully\n");
    }

    return 0;
}

// Function to calculate the IP header checksum
uint16_t calculate_checksum(uint16_t *buf, int nwords) {
    uint32_t sum = 0;
    for (int i = 0; i < nwords; i++) {
        sum += buf[i];
    }
    // Add carry bits to the sum
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    // Take the one's complement of the sum
    return (uint16_t)(~sum);
}

void update_ip_header_checksum(struct ip *ip_header) {
    ip_header->ip_sum = 0; // Set checksum field to 0
    ip_header->ip_sum = calculate_checksum((uint16_t *)ip_header, ip_header->ip_hl * 2);
}

// Pseudo-header structure for checksum calculation
struct pseudo_header {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t length;
};

// Function to update the TCP checksum
void update_tcp_checksum(struct ip *ip_header, struct tcphdr *tcp_header, const u_char *payload, int payload_len) {
    tcp_header->th_sum = 0;

    struct pseudo_header psh;
    psh.src_addr = ip_header->ip_src.s_addr;
    psh.dst_addr = ip_header->ip_dst.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.length = htons(sizeof(struct tcphdr) + payload_len);

    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + payload_len;
    char *pseudogram = malloc(psize);

    memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcp_header, sizeof(struct tcphdr));
    memcpy(pseudogram + sizeof(struct pseudo_header) + sizeof(struct tcphdr), payload, payload_len);

    tcp_header->th_sum = calculate_checksum((uint16_t *)pseudogram, (psize + 1) / 2);

    free(pseudogram);
}

// Function to update the UDP checksum
void update_udp_checksum(struct ip *ip_header, struct udphdr *udp_header, const u_char *payload, int payload_len) {
    udp_header->uh_sum = 0;
    
    struct pseudo_header psh;
    psh.src_addr = ip_header->ip_src.s_addr;
    psh.dst_addr = ip_header->ip_dst.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.length = htons(sizeof(struct udphdr) + payload_len);

    int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + payload_len;
    char *pseudogram = malloc(psize);

    memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), udp_header, sizeof(struct udphdr));
    memcpy(pseudogram + sizeof(struct pseudo_header) + sizeof(struct udphdr), payload, payload_len);

    udp_header->uh_sum = calculate_checksum((uint16_t *)pseudogram, psize / 2);

    free(pseudogram);
}