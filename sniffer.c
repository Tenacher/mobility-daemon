#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/icmpv6.h>

#include "sniffer.h"

#define endless_loop for(;;)

const int PKT_LEN = 20000;

static inline size_t to_bytes(uint8_t mh_hdrlen) {
    return (mh_hdrlen + 1) * 8; // https://www.rfc-editor.org/rfc/rfc6275 for more information about the conversion
}

int sniff_for(MobilityHeaderType mh_type, uint8_t* buffer, struct in6_addr* source) {
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
        
        size_t packet_size = recvfrom(sock, &buf, PKT_LEN, 0, (struct sockaddr*) &addr, &addr_len);

        if(packet_size < 0) {
            perror("Rcvfrom failed!");
            shutdown(sock, SHUT_RDWR);
            return -1;
        }

        struct ip6_mh* mh_ptr = (struct ip6_mh*) buf;
        if(mh_ptr->ip6mh_type != mh_type) {
            continue; //not the specified packet
        }

        memcpy(buffer, buf, to_bytes(mh_ptr->ip6mh_hdrlen));
        memcpy(source, &addr.sin6_addr, sizeof(struct in6_addr));

        shutdown(sock, SHUT_RDWR);
        return 0;
    }
}
