#include "sniffer.h"

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <linux/icmpv6.h>

#include "mobi-packets.h"

#define endless_loop for(;;)

const int PKT_LEN = 20000;

int sniff_for(MobilityHeaderType mh_type, char* buffer, struct in6_addr* source) {
    int sock = socket(AF_INET6, SOCK_RAW, IPPROTO_MH);
    if(sock < 0) {
        perror("Failed to create socket!");
        return -1;
    }

    uint8_t buf[PKT_LEN];
    struct sockaddr_in6 addr;
    addr.sin6_family = AF_INET6;
    socklen_t addr_len = sizeof(struct sockaddr_in6);

    endless_loop {
        
        size_t packet_size = recvfrom(sock, &buf, PKT_LEN, 0, &addr, &addr_len);

        if(packet_size < 0) {
            perror("Rcvfrom failed!");
            shutdown(sock, SHUT_RDWR);
            return -1;
        }

        //char string_addr[INET6_ADDRSTRLEN];
        //inet_ntop(AF_INET6, &addr.sin6_addr, string_addr, INET6_ADDRSTRLEN);
        //printf("%s\n", string_addr);

        struct ip6_mh* mh_ptr = buf;
        if(mh_ptr->ip6mh_type != mh_type) {
            continue; //not the specified packet
        }

        memcpy(buffer, buf, mh_ptr->ip6mh_hdrlen);
        memcpy(source, &addr.sin6_addr, sizeof(struct in6_addr));

        shutdown(sock, SHUT_RDWR);
        return 0;
    }
}
