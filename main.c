//  gcc main.c bpf.c tun.c -lpcap 

#include "pktap.c"
#include "classify.c"
#include "config.h"

int main() {
    if (config_init()!=0) {
        printf("Config error");
        return -1;
    }
  
    classify_INIT();
    return do_pktap_read_all(on_PKTAP_packet, NULL); // OK
}
