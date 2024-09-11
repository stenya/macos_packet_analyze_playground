#ifndef _INJECT_C_
#define _INJECT_C_

#define INJECT_TYPE_PCAP    1
#define INJECT_TYPE_BPF     2

struct inject_handler
{
    int    bpf_fd;
    pcap_t *pcap_handle;
};

int inject_open(int inject_type, const char* ifName, struct inject_handler* handler, void (*bpfOnInPacket)(unsigned char* ip4_header), int bpfIsTun) {
    memset(handler, 0, sizeof(struct inject_handler));

    if (inject_type == INJECT_TYPE_BPF) {
        if (bpfOpen(ifName, &handler->bpf_fd, bpfOnInPacket, bpfIsTun) != 0) {
            fprintf(stderr, "Couldn't open device: %s\n", ifName);
            return -1;
        }
    } else {
        char errbuf[PCAP_ERRBUF_SIZE];
        handler->pcap_handle = pcap_open_live(ifName, BUFSIZ, 0, 0, errbuf);
        if (handler->pcap_handle == NULL) {
            fprintf(stderr, "Couldn't open device: %s\n", errbuf);
            return -2;
        }
    }
    return 0;
}

int inject_close(struct inject_handler* handler) {
    if (handler == NULL) {
        fprintf(stderr, "Invalid handler\n");
        return -1;
    }
    if (handler->bpf_fd != 0)
        bpfClose(handler->bpf_fd);
    handler->bpf_fd = 0;
    
    if (handler->pcap_handle != NULL)        
        pcap_close(handler->pcap_handle);
    handler->pcap_handle = NULL;

    return 0;
}

int inject_packet(struct inject_handler* handler, const void *packet, size_t packet_len) {
    if (handler == NULL) {
        fprintf(stderr, "Invalid handler\n");
        return -1;
    }
    if (handler->bpf_fd != 0) {
        if (write(handler->bpf_fd, packet, packet_len) != packet_len) {
            fprintf(stderr, "Error injecting packet\n");
            return -1;
        }
    } 
    else if (handler->pcap_handle != NULL) {
        if (pcap_inject(handler->pcap_handle, packet, packet_len) == -1) {
            pcap_perror(handler->pcap_handle, "Error injecting packet");
            return -2;
        }
    } else {
        fprintf(stderr, "No handler available\n");
        return -3;
    }
    return 0;
}

#endif //defined(_INJECT_C_)