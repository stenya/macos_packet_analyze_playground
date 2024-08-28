//  gcc main.c bpf.c -lpcap 

#include "pktap.c"
#include "classify.c"
#include "config.h"

int main() {
    if (config_init()!=0) {
        printf("Config error");
        return -1;
    }
  
    classify_openForInjection();
    return do_pktap_read_vTun(classify_func); // OK
}
