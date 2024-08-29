// Build:
//  gcc -o createtun  main_tun.c  

#include "tun.c"

void print_ip_address(struct in_addr ip) {
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip, ip_str, INET_ADDRSTRLEN);
    printf("%s", ip_str);
}

void print_ip_frame(const uint8_t *buffer, ssize_t length) 
{   
    if (length <= 4)
    {
        printf("Bad frame");
        return;
    }

    if  (buffer[3] == AF_INET) {
        const struct ip *ip_hdr = (const struct ip *)(&buffer[4]);
        printf("\nIPv4 Header:\n");
        printf("  Source IP: ");
        print_ip_address(ip_hdr->ip_src);
        printf("\n  Destination IP: ");
        print_ip_address(ip_hdr->ip_dst);
        printf("\n");        

        // Print the remaining data
        printf("Data: ");
        for (ssize_t i = sizeof(struct ip); i < length; i++) {
            printf("%02x ", buffer[i]);
        }
    } else if (buffer[3] == AF_INET6) {
        const struct ip6_hdr *ip6_hdr = (const struct ip6_hdr *)(&buffer[4]);
        printf("\nIPv6 Header:\n");
        char src_ip[INET6_ADDRSTRLEN];
        char dst_ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(ip6_hdr->ip6_src), src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6_hdr->ip6_dst), dst_ip, INET6_ADDRSTRLEN);
        printf("  Source IP: %s\n", src_ip);
        printf("  Destination IP: %s\n", dst_ip);

        // Print the remaining data
        printf("Data: ");
        for (ssize_t i = sizeof(struct ip6_hdr); i < length; i++) {
            printf("%02x ", buffer[i]);
        }
    } else printf("Unknown protocol\n");

    printf("\n");
}

struct tun_handler tunHdlr;

void handle_signal(int signal) {
    printf("Signal %d received\n", signal);
    tun_thread_stop(&tunHdlr);
    printf("Signal %d sent\n", signal);
}

int main(int argc, char *argv[]) {

    char* default_IP = "10.88.88.89";
    char* tun_ip = default_IP;
    if (argc >= 2) 
        tun_ip = argv[1];

    memset(&tunHdlr, 0, sizeof(tunHdlr));

    tunHdlr.cfg_ip = tun_ip;
    tunHdlr.onDataReceived = print_ip_frame;

    if (tun_thread_run(&tunHdlr)!=0) {
        printf("Error creating TUN interface\n");
        return 1;
    }

    printf("TUN interface started\n");

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    printf("Waiting for stop...\n");
    int ret = tun_thread_wait(&tunHdlr);
    printf("TUN interface closed. Return code: %d\n", ret);

    return ret;
}