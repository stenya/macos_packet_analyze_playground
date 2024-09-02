#ifndef __TUN__C__
#define __TUN__C__

#include <unistd.h>
#include <net/if.h>

typedef void (*fn_on_data)(const uint8_t *buffer, ssize_t length);

struct tun_handler{
    // Configuration
    char*       cfg_ip;             // Configuration: IP address to assign to the interface
    char*       cfg_dst_ptp_ip;     // Configuration: Destination point-to-point IP address
    char*       cfg_subnet_mask;    // Configuration: Subnet mask

    fn_on_data  onDataReceived;     // "data received" event handler

    // Info about the initialised interface
    char        ifname[IFNAMSIZ]; // Name of the TUN interface; Initialized by tun_thread_run

    // Internal data    
    int         sock_fd;    // File descriptor for the TUN interface; Initialized by tun_thread_run
    pthread_t   thread;     // Thread ID; Initialized by tun_thread_run
    int         init_done;  // >0 if an error occurred during initialization
};

// Initialize UTUN interface and start the reader thread
// Before calling this function, the following fields must be set:
//  - cfg->cfg_ip (optional)
//  - cfg->onDataReceived (optional)
// Returns 0 on success, 1 on error
// On success, cfg->ifname is initialized
int tun_thread_run(struct tun_handler* hdlr);
ssize_t tun_write(struct tun_handler* hdlr, const void *buffer, size_t buffer_len);
int tun_thread_wait(struct tun_handler* hdlr);
int tun_thread_stop(struct tun_handler* hdlr);

#endif // __TUN__C__