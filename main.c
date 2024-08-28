//  gcc -o createtun  main.c -lpcap 

//#include "tun.c"

#include "pktap.c"


#include "classify_out.c"

#include "config.h"

int main() {
    if (config_init()!=0) {
        printf("Config error");
        return -1;        
    }
  

    pktap_PrepareVPNIfToInjectInFrames(IF_vTUN_NAME, IF_VPN_IP);

    classify_openForInjection();
    return do_pktap_read_vTun(classify_func); // OK
}
