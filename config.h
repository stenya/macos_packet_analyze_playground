#ifndef _CFG_H_
#define _CFG_H_

#include <stdio.h>
#include <net/if.h>
#include <net/ethernet.h>

#include "get_default_addresses.c"

char            IF_DEFAULT_NAME[IFNAMSIZ]           = {0}; // en0
char            IF_DEFAULT_IP_STR[INET_ADDRSTRLEN]  = {0};
struct in_addr  IF_DEFAULT_IP;
unsigned char   IF_DEFAULT_MAC[ETHER_ADDR_LEN]      = {0};    

unsigned char   ROUTER_MAC[ETHER_ADDR_LEN]          = {0};

const char*     IF_VPN_NAME         = "utun5";          // !!!
const char*     IF_VPN_IP_STR       = "172.16.203.231";   // !!!
struct in_addr  IF_VPN_IP;

const char*     VPN_SERVER_IP_STR   = "146.70.78.75";   // !!!

const char*     IF_VTUN_IP_STR      = "172.16.123.123";
const char*     IF_VTUN_PTP_IP_STR  = "172.0.0.255";
const char*     IF_VTUN_MASK_STR    = "255.0.0.0";



int config_init() {
    // Get default configuration parameters:
    // - Default interface name
    // - Default interface MAC address
    // - Default interface IP address
    // - Default router MAC address
    if (get_addresses(IF_DEFAULT_NAME, IF_DEFAULT_MAC, IF_DEFAULT_IP_STR, ROUTER_MAC)!=0) {
        printf("Error obtaining default parameters (interface addresses)");
        return -1;
    }

    if (inet_aton(IF_DEFAULT_IP_STR, &IF_DEFAULT_IP) == 0) {
        printf("Invalid IP address format\n");
        return -1;
    }

    if (inet_aton(IF_VPN_IP_STR, &IF_VPN_IP) == 0) {
        printf("Invalid IP address format\n");
        return -1;
    }

    printf("Router MAC Address: [%02x:%02x:%02x:%02x:%02x:%02x]\n",
        ROUTER_MAC[0], ROUTER_MAC[1], ROUTER_MAC[2],
        ROUTER_MAC[3], ROUTER_MAC[4], ROUTER_MAC[5]);

    printf("Default Interface : [%02x:%02x:%02x:%02x:%02x:%02x] %s (%s)\n", 
        IF_DEFAULT_MAC[0], IF_DEFAULT_MAC[1], IF_DEFAULT_MAC[2],
        IF_DEFAULT_MAC[3], IF_DEFAULT_MAC[4], IF_DEFAULT_MAC[5],
        IF_DEFAULT_NAME, inet_ntoa(IF_DEFAULT_IP));

    printf("VPN IF            : %s (%s)\n", IF_VPN_NAME, inet_ntoa(IF_VPN_IP));
    //printf("TUN Virtual       : %s\n", IF_vTUN_NAME);


    return 0;
}

#endif  //_CFG_H_