#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/route.h>
#include <net/if_dl.h>
#include <sys/sysctl.h>

// Function to get the default interface name
int get_default_interface(char* interface, size_t size) {
    FILE* fp = popen("route get default | grep interface | awk '{print $2}'", "r");
    if (fp == NULL) {
        return -1;
    }
    if (fgets(interface, size, fp) == NULL) {
        pclose(fp);
        return -1;
    }
    interface[strcspn(interface, "\n")] = 0; // Remove newline character
    pclose(fp);
    return 0;
}

// Function to get the IP address of the default interface
int get_ip_address(const char* interface, char* ip_address, size_t size) {
    struct ifaddrs* ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) {
        return -1;
    }
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        if (strcmp(ifa->ifa_name, interface) == 0 && ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in* sa = (struct sockaddr_in*)ifa->ifa_addr;
            inet_ntop(AF_INET, &sa->sin_addr, ip_address, size);
            freeifaddrs(ifaddr);
            return 0;
        }
    }
    freeifaddrs(ifaddr);
    return -1;
}

// Function to get the MAC address of the default interface
int get_mac_address(const char* interface, unsigned char* mac_address) {
    struct ifaddrs* ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) {
        return -1;
    }
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        if (strcmp(ifa->ifa_name, interface) == 0 && ifa->ifa_addr->sa_family == AF_LINK) {
            struct sockaddr_dl* sdl = (struct sockaddr_dl*)ifa->ifa_addr;
            memcpy(mac_address, LLADDR(sdl), sdl->sdl_alen);
            freeifaddrs(ifaddr);
            return 0;
        }
    }
    freeifaddrs(ifaddr);
    return -1;
}

// Function to get the MAC address of the default router
int get_router_mac_address(unsigned char* mac_address) {
    FILE* fp = popen("netstat -rn | grep default | awk '{print $2}'", "r");
    if (fp == NULL) {
        return -1;
    }
    char router_ip[INET_ADDRSTRLEN];
    if (fgets(router_ip, sizeof(router_ip), fp) == NULL) {
        pclose(fp);
        return -1;
    }
    router_ip[strcspn(router_ip, "\n")] = 0; // Remove newline character
    pclose(fp);

    // Use arp to get the MAC address of the router
    char command[256];
    snprintf(command, sizeof(command), "arp -n %s | awk '{print $4}'", router_ip);
    fp = popen(command, "r");
    if (fp == NULL) {
        return -1;
    }
    char mac_str[18];
    if (fgets(mac_str, sizeof(mac_str), fp) == NULL) {
        pclose(fp);
        return -1;
    }
    pclose(fp);
    sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &mac_address[0], &mac_address[1], &mac_address[2],
           &mac_address[3], &mac_address[4], &mac_address[5]);
    return 0;
}

int get_addresses(
    char*           out_DefIfName,    // char[IFNAMSIZ]           16
    unsigned char*  out_DefIfMAC,     // char[ETHER_ADDR_LEN]     6
    char*           out_DefIfIPv4,    // char[INET_ADDRSTRLEN]    16
    unsigned char*  out_RouterMAC     // char[ETHER_ADDR_LEN]     6
) {
    // Get default interface name
    if (get_default_interface(out_DefIfName, sizeof(IFNAMSIZ)) != 0) {
        printf("Failed to get default interface\n");
        return -1;
    }
    printf("Default Interface: %s\n", out_DefIfName);

    // Get IP address of default interface
    if (get_ip_address(out_DefIfName, out_DefIfIPv4, INET_ADDRSTRLEN) != 0) {
        printf("Failed to get IP address\n");
        return -1;
    }
    printf("IP Address: %s\n", out_DefIfIPv4);

    // Get MAC address of default interface
    if (get_mac_address(out_DefIfName, out_DefIfMAC) != 0) {
        printf("Failed to get MAC address\n");
        return -1;
    }
    printf("MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
           out_DefIfMAC[0], out_DefIfMAC[1], out_DefIfMAC[2],
           out_DefIfMAC[3], out_DefIfMAC[4], out_DefIfMAC[5]);

    // Get MAC address of default router
    if (get_router_mac_address(out_RouterMAC) != 0) {
        printf("Failed to get router MAC address\n");
        return -1;
    }
    printf("Router MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
           out_RouterMAC[0], out_RouterMAC[1], out_RouterMAC[2],
           out_RouterMAC[3], out_RouterMAC[4], out_RouterMAC[5]);

    return 0;
}