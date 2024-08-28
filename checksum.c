
#ifndef _CHECKSUM_C_
#define _CHECKSUM_C_

#include <netinet/ip.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <stdio.h>

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

#endif //_CHECKSUM_C_