
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string.h>
#include <net/ethernet.h>

// Function to inject packets
void inject_packet(pcap_t *handle) {
    u_char packet[42]; // Example packet size

    // Fill the packet with some data (Ethernet + IP header)
    struct ether_header *eth_header = (struct ether_header *)packet;
    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));

    // Ethernet header
    memset(eth_header->ether_dhost, 0xff, ETHER_ADDR_LEN); // Broadcast
    memset(eth_header->ether_shost, 0x00, ETHER_ADDR_LEN); // Source MAC (example)
    eth_header->ether_type = htons(ETHERTYPE_IP);

    // IP header
    ip_header->ip_v = 4;
    ip_header->ip_hl = 5;
    ip_header->ip_tos = 0;
    ip_header->ip_len = htons(sizeof(struct ip));
    ip_header->ip_id = htons(54321);
    ip_header->ip_off = 0;
    ip_header->ip_ttl = 64;
    ip_header->ip_p = IPPROTO_TCP;
    ip_header->ip_sum = 0; // Kernel will fill the correct checksum
    inet_pton(AF_INET, "123.124.125.126", &(ip_header->ip_src)); // Source IP
    inet_pton(AF_INET, "131.132.133.134", &(ip_header->ip_dst)); // Destination IP

    // Inject the packet
    if (pcap_inject(handle, packet, sizeof(packet)) == -1) {
        pcap_perror(handle, "Error injecting packet");
    } else {
        printf("Packet injected successfully\n");
    }
}

unsigned long total = 0; 

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ether_header *eth_header;
    struct ip *ip_header;

    // Parse Ethernet header
    eth_header = (struct ether_header *)packet;

    printf("%ld Ethernet Header (type=%d): \n", ++total, ntohs(eth_header->ether_type));
    printf("\tSource MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_header->ether_shost[0], eth_header->ether_shost[1],
           eth_header->ether_shost[2], eth_header->ether_shost[3],
           eth_header->ether_shost[4], eth_header->ether_shost[5]);
    printf("\tDestination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_header->ether_dhost[0], eth_header->ether_dhost[1],
           eth_header->ether_dhost[2], eth_header->ether_dhost[3],
           eth_header->ether_dhost[4], eth_header->ether_dhost[5]);

    // Check if the packet is IP
    if ( ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        ip_header = (struct ip *)(packet + sizeof(struct ether_header));

        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

        printf("IP Header: \n");
        printf("\tSource IP: %s\n", src_ip);
        printf("\tDestination IP: %s\n", dst_ip);
        printf("\tProtocol: %d\n", ip_header->ip_p);
    }

    printf("\n");
}

int DoLibPcap_TEST() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Open the default network device (usually "en0" on macOS)
    handle = pcap_open_live("en0", BUFSIZ, 1, 1, errbuf);
    //handle = pcap_open_live("utun5", BUFSIZ, 1, 1, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return 1;
    }

    inject_packet(handle);
    
    // Start the packet capture loop
    //pcap_loop(handle, 0, packet_handler, NULL);

    // Close the capture handle
    pcap_close(handle);

    return 0;
}
