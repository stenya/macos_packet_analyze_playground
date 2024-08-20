#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <net/if.h>
#include <net/bpf.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#define BPF_BUFFER_LENGTH 4096*1

int DoBpf_TEST() {
    int bpf_fd;
    int i;
    char bpf_device[12];
    char buffer[BPF_BUFFER_LENGTH];
    struct ifreq ifr;
    struct bpf_program filter;
    struct bpf_hdr *bpf_header;
    struct ether_header *eth_header;
    struct ip *ip_header;
    char *packet;
    ssize_t length;
    u_int packet_len;

    struct bpf_insn instructions[] = {
        // Capture all packets
        BPF_STMT(BPF_RET | BPF_K, (u_int)-1)
    };

    // Find an available BPF device
    for (i = 0; i < 255; i++) {
        snprintf(bpf_device, sizeof(bpf_device), "/dev/bpf%d", i);
        bpf_fd = open(bpf_device, O_RDWR);
        if (bpf_fd != -1) {
            printf("Using BPF device: %s\n", bpf_device);
            break;
        }
    }

    if (bpf_fd == -1) {
        perror("Failed to open BPF device");
        return 1;
    }

    // Attach the BPF device to the default network interface
    strncpy(ifr.ifr_name, "en0", sizeof(ifr.ifr_name)); // "en0" is typically the default interface
    //strncpy(ifr.ifr_name, "utun5", sizeof(ifr.ifr_name)); // "en0" is typically the default interface
    if (ioctl(bpf_fd, BIOCSETIF, &ifr) == -1) {
        perror("Failed to set interface");
        close(bpf_fd);
        return 1;
    }

    // Set the BPF filter (optional, here it captures all packets)
    filter.bf_len = sizeof(instructions) / sizeof(struct bpf_insn);
    filter.bf_insns = instructions;
    if (ioctl(bpf_fd, BIOCSETF, &filter) == -1) {
        perror("Failed to set BPF filter");
        close(bpf_fd);
        return 1;
    }

    // Set immediate mode (optional, reduces latency)
    int immediate = 1;
    if (ioctl(bpf_fd, BIOCIMMEDIATE, &immediate) == -1) {
        perror("Failed to set immediate mode");
        close(bpf_fd);
        return 1;
    }

    // Read packets from the BPF device
    while (1) {
        length = read(bpf_fd, buffer, BPF_BUFFER_LENGTH);
        if (length == -1) {
            perror("Failed to read from BPF device");
            break;
        }

        // Process each packet in the buffer
        packet = buffer;
        while (packet < buffer + length) {
            bpf_header = (struct bpf_hdr *)packet;
            packet_len = bpf_header->bh_caplen;
            packet += bpf_header->bh_hdrlen;

            printf("Captured %u bytes\n", packet_len);

            if (bpf_header->bh_caplen != bpf_header->bh_datalen) {
                printf("Packet was truncated\n");
                continue;
            }

            // Parse Ethernet header
            eth_header = (struct ether_header *)packet;
            printf("Ethernet Header: \n");
            printf("\tSource MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   eth_header->ether_shost[0], eth_header->ether_shost[1],
                   eth_header->ether_shost[2], eth_header->ether_shost[3],
                   eth_header->ether_shost[4], eth_header->ether_shost[5]);
            printf("\tDestination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   eth_header->ether_dhost[0], eth_header->ether_dhost[1],
                   eth_header->ether_dhost[2], eth_header->ether_dhost[3],
                   eth_header->ether_dhost[4], eth_header->ether_dhost[5]);

            // Check if the packet is IP
            if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
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
break;
            //char* oldPacket = packet;
            
            //printf("BPF_WORDALIGN:%ld\n", BPF_WORDALIGN(bpf_header->bh_caplen + bpf_header->bh_hdrlen));

            // Move to the next packet
            //packet += BPF_WORDALIGN(packet_len);

            //packet += BPF_WORDALIGN(bpf_header->bh_caplen + bpf_header->bh_hdrlen);
            packet += ip_header->ip_len;
            // bpf_header->bh_caplen + bpf_header->bh_hdrlen;

            //printf("DIFF: %ld (BPF_WORDALIGN:%ld)", packet - oldPacket, BPF_WORDALIGN(packet_len));
        }
    }

    close(bpf_fd);
    return 0;
}