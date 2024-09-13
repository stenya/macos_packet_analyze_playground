#ifndef _DO_BPF_C_
#define _DO_BPF_C_

#include "bpf.h"

#include <pthread.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <net/if.h>
#include <net/bpf.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include <errno.h> 

#define DEFAULT_BUFFER_SIZE 16 * 1024 * 1024
void* bpf_read_thread(void *bpf_fd);

struct bpf_dev_handler {
    int bpf_fd;
    void (*onDataReceived)(unsigned char* ip4_header);
    int isTunInterface;
    int read_buff_size;
}; 

int bpfOpen(const char *interface, int *bpf_fd, void (*onDataReceived)(unsigned char* ip4_header), int isTunInterface) {
    char bpf_device[12];
    struct ifreq ifr;
    int i;

    // Find an available BPF device
    for (i = 0; i < 255; i++) {
        snprintf(bpf_device, sizeof(bpf_device), "/dev/bpf%d", i);
        *bpf_fd = open(bpf_device, O_RDWR);
        if (*bpf_fd != -1) {
            printf("Using BPF device: %s\n", bpf_device);
            break;
        }
    }

    if (*bpf_fd == -1) {
        perror("Failed to open BPF device");
        return -1;
    }

    // Set buffer size
    int buffer_size = DEFAULT_BUFFER_SIZE;
    if (ioctl(*bpf_fd, BIOCSBLEN, &buffer_size) == -1) {
        perror("Failed to set buffer size");
        close(*bpf_fd);
        return -1;
    }

    // Attach the BPF device to the specified network interface
    strncpy(ifr.ifr_name, interface, sizeof(ifr.ifr_name));
    if (ioctl(*bpf_fd, BIOCSETIF, &ifr) == -1) {
        perror("Failed to set interface");
        close(*bpf_fd);
        return -1;
    }

    // Set immediate mode
    int immediate = 1;
    if (ioctl(*bpf_fd, BIOCIMMEDIATE, &immediate) == -1) {
        perror("Failed to set immediate mode");
        close(*bpf_fd);
        return -1;
    }

    // Set see-sent mode to false
    int see_sent = 0;
    if (ioctl(*bpf_fd, BIOCSSEESENT, &see_sent) == -1) {
        perror("Failed to set see-sent mode");
        close(*bpf_fd);
        return -1;
    }

    // Set non-blocking mode
    if (fcntl(*bpf_fd, F_SETFL, O_NONBLOCK) == -1) {
        perror("Failed to set non-blocking mode");
        close(*bpf_fd);
        return -1;
    }

    // Create the thread
    if (onDataReceived) {
        struct bpf_dev_handler* hdlr = (struct bpf_dev_handler*)malloc(sizeof(struct bpf_dev_handler));
        hdlr->bpf_fd = *bpf_fd;
        hdlr->onDataReceived = onDataReceived;
        hdlr->isTunInterface = isTunInterface;
        hdlr->read_buff_size = buffer_size;

        printf("Creating BPF reader thread\n");
        pthread_t   thread;
        if (pthread_create(&thread, NULL, bpf_read_thread, hdlr) != 0) {
            perror("Failed to create thread");
            return -1;
        }    
    }
    return 0;
}

ssize_t bpfWrite(int bpf_fd, const void *packet, size_t packet_len) {
    return write(bpf_fd, packet, packet_len);    
}

void bpfClose(int bpf_fd) {
    close(bpf_fd);
}


void* bpf_read_thread(void *arg) {
    struct bpf_dev_handler* hdlr = (struct bpf_dev_handler*)arg;

    printf("BPF reader thread started\n");
        
    // Read packets from the BPF device
    char* buffer = malloc(hdlr->read_buff_size);
    memset(buffer, 0, hdlr->read_buff_size);

    int exit = 0;
    while (!exit)
    {        
        ssize_t length;
        while (1) {
            length = read(hdlr->bpf_fd, buffer, hdlr->read_buff_size);
            if (length == -1) {
                if (errno == EINTR) {
                    continue; // Retry if interrupted by a signal
                } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    // Resource temporarily unavailable, wait and retry
                    // usleep(1000); // Sleep for 1 millisecond
                    continue;
                } else {
                    perror("Failed to read from BPF device");
                    exit = 1;
                    break;
                }
            }
            break; // Successfully read data
        }
        if (exit) 
            break;

        int offset = 0;
        while (offset <  length) {
            struct bpf_hdr *bpf_header = (struct bpf_hdr *)(buffer + offset);
            u_char *packet_data = (u_char *)(buffer + offset + bpf_header->bh_hdrlen);

            // Move to the next packet in the buffer
            offset += BPF_WORDALIGN(bpf_header->bh_hdrlen + bpf_header->bh_caplen);
            
            // AF_INET???
            if (bpf_header->bh_caplen < bpf_header->bh_datalen) {
                printf("Packet truncated\n");
                break;
            }

            // Parse Ethernet header
            if (hdlr->isTunInterface) {
                // For TUN/TAP interfaces, data starts with "02 00 00 00" (AF_INET)
                // and the Ethernet header is not present.
                // We should check the first 4 bytes and skip the Ethernet header if not present.
                
                //uint32_t protocol_family = ntohl(*(uint32_t *)packet_data);
                //if (protocol_family != AF_INET) // IPv4
                //   continue;
                uint32_t protocol_family = *(uint32_t *)packet_data;
                if (protocol_family != AF_INET) // IPv4
                   continue;
                
                struct ip *ip_header = (struct ip *)(packet_data + 4);
                if (hdlr->onDataReceived)
                    hdlr->onDataReceived((unsigned char*) ip_header);     
            } else {
                struct ether_header *eth_header = (struct ether_header *)packet_data;
                int ethType = ntohs(eth_header->ether_type);   
                if (ethType != ETHERTYPE_IP) // TODO: ETHERTYPE_IPV6
                {
                    continue;
                }
                struct ip *ip_header = (struct ip *)(packet_data + sizeof(struct ether_header));
                if (hdlr->onDataReceived)
                    hdlr->onDataReceived((unsigned char*) ip_header);
            }
        }
    
    }

    free(hdlr);
    free(buffer);

    return NULL;
}


#endif //_DO_BPF_C_