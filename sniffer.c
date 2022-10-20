#include "sniffer.h"

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <linux/icmpv6.h>


#define endless_loop for(;;)

const int PKT_LEN = 20000;

int sniff_bu(char* buffer) {
    int sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if(sock < 0) {
        perror("Failed to create socket!");
        return -1;
    }

    char buf[PKT_LEN];
    struct sockaddr_in6 addr;
    addr.sin6_family = AF_INET6;
    socklen_t addr_len = sizeof(struct sockaddr_in6);

    endless_loop {
        
        size_t packet_size = recvfrom(sock, &buf, PKT_LEN, 0, &addr, &addr_len);

        if(packet_size < 0) {
            perror("Rcvfrom failed!");
            return -1;
        }

        char string_addr[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &addr.sin6_addr, string_addr, INET6_ADDRSTRLEN);
        printf("%s\n", string_addr);

        struct icmp6hdr* a = buf;

        printf("%d\n", a->icmp6_type);
        return 0;

    }    

    return 0;
}

int sniff_b_ack(char* buffer) {
    return 0;
}

int sniff_for(MobilityHeaderType type, char* buffer) {
    switch (type) {
    case BU:
        return sniff_bu(buffer);
    case B_ACK:
        return sniff_b_ack(buffer);
    default:
        return -1;
    }
}