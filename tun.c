// Build:
//  gcc -o createtun  main_tun.c  

#include "tun.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pthread.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>

#include <arpa/inet.h>

#include <net/if.h>
#include <net/if_utun.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/if_ether.h>


#define UTUN_CONTROL_NAME "com.apple.net.utun_control"
#define SYSPROTO_CONTROL 2
#define AF_SYS_CONTROL 2

// Function to sleep for a specified number of milliseconds
void sleep_ms(int milliseconds) {
    struct timespec ts;
    ts.tv_sec = milliseconds / 1000;
    ts.tv_nsec = (milliseconds % 1000) * 1000000;
    nanosleep(&ts, NULL);
}


void initDoneWithError(struct tun_handler* hdlr, const char* msg) {
    perror(msg);
    int fd = hdlr->sock_fd; 
    if (fd>=0) {
        hdlr->sock_fd = -1;
        close(fd);        
    }
    hdlr->init_done = 1;
}

int tun_create_and_run_reader_sync(struct tun_handler* hdlr) {
    hdlr->init_done = 0;
    if (hdlr == NULL) {
        initDoneWithError(hdlr, "bad argument");
        return 1;
    }

    struct sockaddr_ctl addr;
    struct ctl_info ctl_info;
    struct ifreq ifr;

    // Step 1: Create a socket
    hdlr->sock_fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (hdlr->sock_fd < 0) {
        initDoneWithError(hdlr, "socket");
        return 1;
    }

    // Step 2: Prepare the control ID
    memset(&ctl_info, 0, sizeof(ctl_info));
    strncpy(ctl_info.ctl_name, UTUN_CONTROL_NAME, MAX_KCTL_NAME);
    if (ioctl(hdlr->sock_fd, CTLIOCGINFO, &ctl_info) < 0) {
        initDoneWithError(hdlr, "ioctl");
        return 1;
    }

    // Step 3: Bind the socket
    memset(&addr, 0, sizeof(addr));
    addr.sc_len = sizeof(addr);
    addr.sc_family = AF_SYSTEM;
    addr.ss_sysaddr = AF_SYS_CONTROL;
    addr.sc_id = ctl_info.ctl_id;
    addr.sc_unit = 0; // Let the kernel choose the unit number

    if (connect(hdlr->sock_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        initDoneWithError(hdlr, "connect");
        return 1;
    }

    // Step 4: Get the interface name
    socklen_t ifname_len = sizeof(hdlr->ifname);
    if (getsockopt(hdlr->sock_fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, hdlr->ifname, &ifname_len) < 0) {
        initDoneWithError(hdlr, "getsockopt");
        return 1;
    }
    printf("Created utun interface: %s\n", hdlr->ifname);

    // Step 5: Configure the interface (example: set IP address)
    if (hdlr 
            && 
            (hdlr->cfg_ip != NULL
            || hdlr->cfg_dst_ptp_ip != NULL
            || hdlr->cfg_subnet_mask != NULL)
        ) {
        int fd_config = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd_config < 0) {
            initDoneWithError(hdlr, "socket");
            return 1;
        }

        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, hdlr->ifname, IFNAMSIZ);
        struct sockaddr_in *addr_in = (struct sockaddr_in *)&ifr.ifr_addr;
        addr_in->sin_family = AF_INET;

        // Set the IP address
        if (hdlr->cfg_ip != NULL) {            
            inet_pton(AF_INET, hdlr->cfg_ip, &addr_in->sin_addr);
            if (ioctl(fd_config, SIOCSIFADDR, &ifr) == -1) {
                close(fd_config);
                initDoneWithError(hdlr, "ioctl SIOCSIFADDR");
                return 1;
            }
        }
    
        // Set the destination address (point-to-point)
        if (hdlr->cfg_dst_ptp_ip != NULL) {            
            inet_pton(AF_INET, hdlr->cfg_dst_ptp_ip, &addr_in->sin_addr);
            if (ioctl(fd_config, SIOCSIFDSTADDR, &ifr) == -1) {
                close(fd_config);
                initDoneWithError(hdlr, "ioctl SIOCSIFDSTADDR");
                return 1;
            }
        }

        // Set the subnet mask
        if (hdlr->cfg_subnet_mask != NULL) {
            inet_pton(AF_INET, hdlr->cfg_subnet_mask, &addr_in->sin_addr);
            if (ioctl(fd_config, SIOCSIFNETMASK, &ifr) == -1) {
                close(fd_config);
                initDoneWithError(hdlr, "ioctl SIOCSIFNETMASK");
                return 1;
            }
        }

        close(fd_config);
        printf("Assigned IP address to %s\n", hdlr->ifname);
    }

    hdlr->init_done = 1; // release tun_thread_run(). hdlr->sock_fd and hdlr->ifname are initialised 
    
    //*
    char buffer[4096];  // TODO: size to use?
    ssize_t nbytes;

    fn_on_data  funcDataReceived = hdlr->onDataReceived;

    printf("[!] Listening for data on %s...\n", hdlr->ifname);
    while (hdlr->sock_fd>=0) {
        nbytes = read(hdlr->sock_fd, buffer, sizeof(buffer));
        if (nbytes < 0) {
            perror("read");
            break;
        }

        if (funcDataReceived)
            funcDataReceived((const uint8_t *)buffer, nbytes);
    }

    if (hdlr->sock_fd >= 0) {
        close(hdlr->sock_fd);
        hdlr->sock_fd = -1;
    }
    //*/
    return 0;
}

void* tun_thread(void *arg) {
    printf("TUN Start ...\n");
    struct tun_handler* cfg = (struct tun_handler*)arg;
    int result = tun_create_and_run_reader_sync(cfg);
    return (void *)(intptr_t)result;
}

int tun_thread_run(struct tun_handler* hdlr) {
    if (hdlr == NULL) {
        return 1;
    }
    
    // Create the thread
    if (pthread_create(&hdlr->thread, NULL, tun_thread, hdlr) != 0) {
        perror("Failed to create thread");
        return 1;
    }

    //  wait for the thread to complete initialization
    while (hdlr->init_done == 0)    
        sleep_ms(1);

    return 0;
}

int tun_thread_wait(struct tun_handler* hdlr) {
    void *thread_result;

    // Wait for the thread to complete
    if (pthread_join(hdlr->thread, &thread_result) != 0) {
        perror("Failed to join thread");
        return 1;
    }
    // Get the result from the thread
    int result = (int)(intptr_t)thread_result;
    printf("Stopped. Returned: %d\n", result);

    return result;
}

int tun_thread_stop(struct tun_handler* hdlr) {    
    int ret = close(hdlr->sock_fd);
    hdlr->sock_fd = 0;
    return ret;
}

ssize_t tun_write(struct tun_handler* hdlr, const void *buffer, size_t buffer_len) {
    ssize_t bytes_written;
    
    bytes_written = write(hdlr->sock_fd, buffer, buffer_len);
    if (bytes_written == -1) {
        perror("Write error");
    }
    return bytes_written;
}