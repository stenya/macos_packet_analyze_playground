// Build:
//  gcc -o pktaptest  main_pktap.c -lpcap

#include "pktap.c"

pcap_t *pcap = NULL;

void handle_signal(int signal) {
    printf("Signal %d received\n", signal);
    if (pcap!=NULL)
        pcap_breakloop(pcap);
}

int on_PKTAP_pkt(const struct pktap_header *pktapHdr, struct ip* ip4Hdr) 
{
  // packet can be analyzed here
  return 0;
}

int main(int argc, char *argv[]) {
    _pktap_debug = 1; // print packets info to console

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    return do_pktap_read_all(on_PKTAP_pkt, &pcap); 
}