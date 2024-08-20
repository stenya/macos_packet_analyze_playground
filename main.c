//  gcc -o createtun  main.c -lpcap 

//#include "tun.c"

#include "pktap.c"

#include "get_default_addresses.c"
#include "inject.c"

int main() {
    char interfaceName[IFNAMSIZ]                = {0};
    char ip_en0[INET_ADDRSTRLEN]                = {0};
    unsigned char mac_en0_bytes[ETHER_ADDR_LEN] = {0};    
    unsigned char mac_rtr_bytes[ETHER_ADDR_LEN] = {0};

    // Get default configuration parameters:
    // - Default interface name
    // - Default interface MAC address
    // - Default interface IP address
    // - Default router MAC address
    if (get_addresses(interfaceName, mac_en0_bytes, ip_en0, mac_rtr_bytes)!=0) {
        printf("Error obtaining default parameters (interface addresses)");
        return -1;
    }

    struct in_addr ipAddrEn0;
    if (inet_aton(ip_en0, &ipAddrEn0) == 0) {
        printf("Invalid IP address format\n");
        return -1;
    }


   //return CreateUTUN();

    openForInjection(interfaceName, mac_en0_bytes, ipAddrEn0, mac_rtr_bytes, "utun9");
    return DoPktap(inject_func); // OK
}


/*
// Function to convert MAC address string to byte array
int mac_str_to_byte_array(const char* mac_str, unsigned char* mac_bytes) {
    if (mac_str == NULL || mac_bytes == NULL) {
        return -1; // Error: Null pointer
    }

    int values[6];
    if (sscanf(mac_str, "%x:%x:%x:%x:%x:%x", 
               &values[0], &values[1], &values[2], 
               &values[3], &values[4], &values[5]) != 6) {
        return -1; // Error: Invalid MAC address format
    }

    for (int i = 0; i < 6; ++i) {
        mac_bytes[i] = (unsigned char)values[i];
    }

    return 0; // Success
}*/
