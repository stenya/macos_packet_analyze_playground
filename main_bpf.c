// Build:
//  gcc -o bpftest  main_bpf.c bpf.c 

#include "bpf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> 
#include <netinet/ip.h> 
#include <arpa/inet.h> 
#include <sys/param.h>
#include "print_frame_helpers.c" 


void onDataReceived(unsigned char* ip4_header) {
    print_ip_4((const struct ip*)ip4_header, "");
}

int main(int argc, char *argv[]) {
    char *interface = "utun4";//"en0";
    int isTUN = 1;

    int bpf_fd;
    if (bpfOpen(interface, &bpf_fd, onDataReceived, isTUN) == -1) {
        return -1;
    };

    while(1) {
        sleep(100);
    }
    return 0;
}