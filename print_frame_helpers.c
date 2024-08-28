
#ifndef _PRINT_FRAME_HELPERS_C_
#define _PRINT_FRAME_HELPERS_C_

#include "inc/pktap.h"
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

void print_pktap_header(const struct pktap_header *pktapHdr, const char* prefix)
{
    printf("%s%s IF='%s' | ipproto: %02d | family: %02d | pid: %04d | proc: %s \n", 
        prefix,
        (pktapHdr->pth_flags&PTH_FLAG_DIR_OUT)?"OUT" : ((pktapHdr->pth_flags&PTH_FLAG_DIR_IN)?"IN ": "???"),
        pktapHdr->pth_ifname,
        pktapHdr->pth_ipproto, 
        pktapHdr->pth_protocol_family,            
        pktapHdr->pth_pid, 
        pktapHdr->pth_comm);
}

void print_ether_header(const struct ether_header* eth_header, const char* prefix)
{
    printf("%sEthernet Header (type=%d): Source MAC: %02x:%02x:%02x:%02x:%02x:%02x, Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
        prefix,
        ntohs(eth_header->ether_type),
        eth_header->ether_shost[0], eth_header->ether_shost[1], eth_header->ether_shost[2],
        eth_header->ether_shost[3], eth_header->ether_shost[4], eth_header->ether_shost[5],
        eth_header->ether_dhost[0], eth_header->ether_dhost[1], eth_header->ether_dhost[2],
        eth_header->ether_dhost[3], eth_header->ether_dhost[4], eth_header->ether_dhost[5]);
}

void print_ip_4(const struct ip* ipHdr, const char* prefix)
{
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    strcpy(src_ip, inet_ntoa(ipHdr->ip_src));
    strcpy(dst_ip, inet_ntoa(ipHdr->ip_dst));
    printf("%sIP(%d): proto=%d [%s] ==> [%s]\n", 
        prefix,
        ipHdr->ip_v, ipHdr->ip_p, src_ip, dst_ip);

    //printf("  Version: %d\n", ipHdr->ip_v);
    //printf("  Header Length: %d (bytes)\n", ipHdr->ip_hl * 4);
    //printf("  Type of Service: %d\n", ipHdr->ip_tos);
    //printf("  Total Length: %d\n", ntohs(ipHdr->ip_len));
    //printf("  Identification: %d\n", ntohs(ipHdr->ip_id));
    //printf("  Flags and Fragment Offset: %d\n", ntohs(ipHdr->ip_off));
    //printf("  Time to Live: %d\n", ipHdr->ip_ttl);
    //printf("  Protocol: %d\n", ipHdr->ip_p);
    //printf("  Header Checksum: %d\n", ntohs(ipHdr->ip_sum));
    //printf("  Source IP: %s\n", inet_ntoa(ipHdr->ip_src));
    //printf("  Destination IP: %s\n", inet_ntoa(ipHdr->ip_dst));
}

void print_ip_6(const struct ip6_hdr* ip6Hdr, const char* prefix)
{
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &(ip6Hdr->ip6_src), src_ip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ip6Hdr->ip6_dst), dst_ip, INET6_ADDRSTRLEN);
    printf("%sIP(%d): [%s] ==> [%s] PayloadLen=%d\n", 
        prefix,
        ip6Hdr->ip6_vfc, src_ip, dst_ip, ntohs(ip6Hdr->ip6_plen));

    //printf("  Version: %d\n", ip6Hdr->ip6_vfc);
    //printf("  Traffic Class: %d\n", ip6Hdr->ip6_flow);
    //printf("  Flow Label: %d\n", ip6Hdr->ip6_flow);
    //printf("  Payload Length: %d\n", ntohs(ip6Hdr->ip6_plen));
    //printf("  Next Header: %d\n", ip6Hdr->ip6_nxt);
    //printf("  Hop Limit: %d\n", ip6Hdr->ip6_hlim);
    //printf("  Source IP: %s\n", src_ip);
    //printf("  Destination IP: %s\n", dst_ip);
}

void print_tcphdr(const struct tcphdr* tcpHdr, const char* prefix)
{
    printf("%sTCP: SPort=%d DPort=%d\n", 
            prefix,
            ntohs(tcpHdr->th_sport), 
            ntohs(tcpHdr->th_dport));
    //printf("  TCP Header: \n");
    //printf("    Source Port: %d\n", ntohs(tcpHdr->th_sport));
    //printf("    Destination Port: %d\n", ntohs(tcpHdr->th_dport));
    //printf("    Payload Length: %d\n", payload_length);
    //printf("    Sequence Number: %u\n", ntohl(tcpHdr->th_seq));
    //printf("    Acknowledgment Number: %u\n", ntohl(tcpHdr->th_ack));
    //printf("    Data Offset: %d (bytes)\n", tcpHdr->th_off * 4);
    //printf("    Flags: %d\n", tcpHdr->th_flags);
    //printf("    Window: %d\n", ntohs(tcpHdr->th_win));
    //printf("    Checksum: %d\n", ntohs(tcpHdr->th_sum));
    //printf("    Urgent Pointer: %d\n", ntohs(tcpHdr->th_urp));
}

void print_udphdr(const struct udphdr* udpHdr, const char* prefix)
{
    printf("%sUDP: SPort=%d DPort=%d PayloadLen=%ld\n", 
            prefix,
            ntohs(udpHdr->uh_sport), 
            ntohs(udpHdr->uh_dport), 
            ntohs(udpHdr->uh_ulen) - sizeof(struct udphdr));       

    //printf("  UDP Header: \n");
    //printf("    Source Port: %d\n", ntohs(udpHdr->uh_sport));
    //printf("    Destination Port: %d\n", ntohs(udpHdr->uh_dport));
    //printf("    Length: %d\n", ntohs(udpHdr->uh_ulen));
    //printf("    Payload Length: %d\n", ntohs(udpHdr->uh_ulen) - sizeof(struct udphdr));
    //printf("    Checksum: %d\n", ntohs(udpHdr->uh_sum));
}

int print_pktap_header_all_details(const struct pktap_header *pktapHdr, unsigned char* ipData, unsigned int len) 
{
    if (pktapHdr == NULL || ipData == NULL) 
        return -1;

    print_pktap_header(pktapHdr, "");

    // TODO: currently we are using only IPV4. We must support IPv6 also!
    if (len < sizeof(struct ip))
        return -2;

    const struct ip *ipHdr   = NULL;
    const struct tcphdr *tcpHdr = NULL;
    const struct udphdr *udpHdr = NULL;
    
    if (pktapHdr->pth_protocol_family == AF_INET) {
        // IPv4 header
        ipHdr   = (const struct ip *)ipData;
        if (ipHdr!=NULL) 
        {
            if (ipHdr->ip_p == IPPROTO_TCP) 
                tcpHdr = (const struct tcphdr *)((const u_char *)ipHdr + ipHdr->ip_hl * 4);
            else if (ipHdr->ip_p == IPPROTO_UDP)
                udpHdr = (const struct udphdr *)((const u_char *)ipHdr + ipHdr->ip_hl * 4);
            
            print_ip_4(ipHdr, "");            
        }
    } 
    else if (pktapHdr->pth_protocol_family == AF_INET6)
    {
        // IPv6 header
        const struct ip6_hdr *ip6Hdr = (const struct ip6_hdr *)ipData;
        if (ip6Hdr!=NULL) 
        {
            if (ip6Hdr->ip6_nxt == IPPROTO_TCP) 
                tcpHdr = (const struct tcphdr *)((const u_char *)ip6Hdr + sizeof(struct ip6_hdr));
            else if (ip6Hdr->ip6_nxt == IPPROTO_UDP)
                udpHdr = (const struct udphdr *)((const u_char *)ip6Hdr + sizeof(struct ip6_hdr));

            print_ip_6(ip6Hdr, "");
        }
    }
    else
    {
        return -2;
    }

    if (tcpHdr!=NULL)       print_tcphdr(tcpHdr, "");
    else if (udpHdr!=NULL)  print_udphdr(udpHdr, "");

    return 0;
} 

#endif // _PRINT_FRAME_HELPERS_C_