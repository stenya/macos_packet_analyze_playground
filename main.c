//  gcc -o createtun  main.c -lpcap 

//#include "tun.c"

#include "pktap.c"

#include "get_default_addresses.c"
#include "inject.c"

int main() {
    char            out_DefIfName[IFNAMSIZ]         = {0};
    char            out_DefIfIPv4[INET_ADDRSTRLEN]  = {0};
    unsigned char   out_DefIfMAC[ETHER_ADDR_LEN]    = {0};    
    unsigned char   out_RouterMAC[ETHER_ADDR_LEN]   = {0};

    // Get default configuration parameters:
    // - Default interface name
    // - Default interface MAC address
    // - Default interface IP address
    // - Default router MAC address
    if (get_addresses(out_DefIfName, out_DefIfMAC, out_DefIfIPv4, out_RouterMAC)!=0) {
        printf("Error obtaining default parameters (interface addresses)");
        return -1;
    }

    struct in_addr ipAddrEn0;
    if (inet_aton(out_DefIfIPv4, &ipAddrEn0) == 0) {
        printf("Invalid IP address format\n");
        return -1;
    }
   //return CreateUTUN();

    char *virtualTunName = "utun5";
    openForInjection(out_DefIfName, out_DefIfMAC, ipAddrEn0, out_RouterMAC, virtualTunName);
    return DoPktap(inject_func); // OK
}
