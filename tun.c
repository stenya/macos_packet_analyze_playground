#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <net/if.h>
#include <net/if_utun.h>
#include <arpa/inet.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>

#define UTUN_CONTROL_NAME "com.apple.net.utun_control"
#define SYSPROTO_CONTROL 2
#define AF_SYS_CONTROL 2

// Build:
//  gcc -o createtun  main.c  

// -----------------------------------------------------------
volatile sig_atomic_t stop = 0;
void handle_signal(int signal) {
    stop = 1;
}

// -----------------------------------------------------------
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <net/ethernet.h> 

// Function to print MAC address
void print_mac_address(const uint8_t *mac) {
    for (int i = 0; i < ETHER_ADDR_LEN; i++) {
        printf("%02x", mac[i]);
        if (i < ETHER_ADDR_LEN - 1) {
            printf(":");
        }
    }
}

// Function to print IP address
void print_ip_address(struct in_addr ip) {
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip, ip_str, INET_ADDRSTRLEN);
    printf("%s", ip_str);
}

// Function to print Ethernet frame data
void print_ethernet_frame(const uint8_t *buffer, ssize_t length) {
    if (length < sizeof(struct ether_header)) {
        printf("Buffer too small for Ethernet frame\n");
        return;
    }

    // Extract and print the Ethernet header
    const struct ether_header *eth = (const struct ether_header *)buffer;
    printf("Ethernet Header:\n");
    printf("  Destination MAC: ");
    print_mac_address(eth->ether_dhost);
    printf("\n  Source MAC: ");
    print_mac_address(eth->ether_shost);
    printf("\n  Ethertype: 0x%04x\n", ntohs(eth->ether_type));

    // Check if the Ethertype indicates an IP packet
    if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
        if (length < sizeof(struct ether_header) + sizeof(struct ip)) {
            printf("Buffer too small for IP packet\n");
            return;
        }

        // Extract and print the IP header
        const struct ip *ip_hdr = (const struct ip *)(buffer + sizeof(struct ether_header));
        printf("\nIP Header:\n");
        printf("  Source IP: ");
        print_ip_address(ip_hdr->ip_src);
        printf("\n  Destination IP: ");
        print_ip_address(ip_hdr->ip_dst);
        printf("\n");
    }

    // Print the remaining data
    printf("Data: ");
    for (ssize_t i = sizeof(struct ether_header); i < length; i++) {
        printf("%02x ", buffer[i]);
    }
    printf("\n");
}

void print_ip_frame(const uint8_t *buffer, ssize_t length) 
{   
    if (length <= 4)
    {
        printf("Bad frame");
        return;
    }

    if  (buffer[3] == AF_INET) {
        const struct ip *ip_hdr = (const struct ip *)(&buffer[4]);
        printf("\nIPv4 Header:\n");
        printf("  Source IP: ");
        print_ip_address(ip_hdr->ip_src);
        printf("\n  Destination IP: ");
        print_ip_address(ip_hdr->ip_dst);
        printf("\n");        

        // Print the remaining data
        printf("Data: ");
        for (ssize_t i = sizeof(struct ip); i < length; i++) {
            printf("%02x ", buffer[i]);
        }
    } else if (buffer[3] == AF_INET6) {
        const struct ip6_hdr *ip6_hdr = (const struct ip6_hdr *)(&buffer[4]);
        printf("\nIPv6 Header:\n");
        char src_ip[INET6_ADDRSTRLEN];
        char dst_ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(ip6_hdr->ip6_src), src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6_hdr->ip6_dst), dst_ip, INET6_ADDRSTRLEN);
        printf("  Source IP: %s\n", src_ip);
        printf("  Destination IP: %s\n", dst_ip);

        // Print the remaining data
        printf("Data: ");
        for (ssize_t i = sizeof(struct ip6_hdr); i < length; i++) {
            printf("%02x ", buffer[i]);
        }
    } else printf("Unknown protocol\n");

    printf("\n");
}

// -----------------------------------------------------------

int CreateUTUN() {
    int sockfd;
    struct sockaddr_ctl addr;
    struct ctl_info ctl_info;
    char ifname[IFNAMSIZ];
    struct ifreq ifr;

    // Step 1: Create a socket
    sockfd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    // Step 2: Prepare the control ID
    memset(&ctl_info, 0, sizeof(ctl_info));
    strncpy(ctl_info.ctl_name, UTUN_CONTROL_NAME, MAX_KCTL_NAME);
    if (ioctl(sockfd, CTLIOCGINFO, &ctl_info) == -1) {
        perror("ioctl");
        close(sockfd);
        return 1;
    }

    // Step 3: Bind the socket
    memset(&addr, 0, sizeof(addr));
    addr.sc_len = sizeof(addr);
    addr.sc_family = AF_SYSTEM;
    addr.ss_sysaddr = AF_SYS_CONTROL;
    addr.sc_id = ctl_info.ctl_id;
    addr.sc_unit = 0; // Let the kernel choose the unit number

    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("connect");
        close(sockfd);
        return 1;
    }

    // Step 4: Get the interface name
    socklen_t ifname_len = sizeof(ifname);
    if (getsockopt(sockfd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname, &ifname_len) == -1) {
        perror("getsockopt");
        close(sockfd);
        return 1;
    }

    printf("Created utun interface: %s\n", ifname);

    // Step 5: Configure the interface (example: set IP address)
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        close(sockfd);
        return 1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    struct sockaddr_in *addr_in = (struct sockaddr_in *)&ifr.ifr_addr;
    addr_in->sin_family = AF_INET;
    inet_pton(AF_INET, "10.88.88.88", &addr_in->sin_addr);

    if (ioctl(fd, SIOCSIFADDR, &ifr) == -1) {
        perror("ioctl");
        close(fd);
        close(sockfd);
        return 1;
    }

    printf("Assigned IP address to %s\n", ifname);
    close(fd);

    //printf("Press any key to exit...\n");
    //getchar();

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    char buffer[4096];
    ssize_t nbytes;

    printf("[!] Listening for data on %s...\n", ifname);
    while (!stop) {
        nbytes = read(sockfd, buffer, sizeof(buffer));
        if (nbytes < 0) {
            perror("read");
            close(sockfd);
            return 1;
        }

        print_ip_frame((const uint8_t *)buffer, nbytes);
        //print_ethernet_frame((const uint8_t *)buffer, nbytes);
        /*
        printf("Received %zd bytes: ", nbytes);
        for (ssize_t i = 0; i < nbytes; i++) {
            printf("%02x ", (unsigned char)buffer[i]);
        }
        printf("\n");
        //*/
    }


    // Keep the socket open if you intend to use it to send/receive packets.
    // For demonstration, we just close it here.
    close(sockfd);
    return 0;
}
