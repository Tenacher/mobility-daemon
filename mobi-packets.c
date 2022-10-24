#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "mobi-packets.h"

uint8_t* create_binding_ack(uint16_t sequence) {
    uint8_t* msg = malloc(16);

    struct ip6_mh* mh = (struct ip6_mh*) msg;
    mh->ip6mh_proto = 59; // No proto
    // RFC: in units of 8 octets excluding the first 8 octets -> 1 hdrlen = 8 bytes + 8 bytes = 16 bytes
    mh->ip6mh_hdrlen = 1; 
    mh->ip6mh_type = 6; // B_ACK type code
    mh->ip6mh_reserved = 0; // RFC: Must be initialized to zero and ignored
    mh->ip6mh_cksum = 0;

    struct mh_back* b_ack = (struct mh_back*) mh->payload;
    b_ack->status = 0; // Binding Update accepted
    b_ack->reserved = 0; // just like above
    b_ack->sequence = htons(sequence); // RFC: same as BU sequence
    b_ack->lifetime = htons(16); // in units of 4 seconds -> 16 lifetime = 16*4 sec = 64 sec

    struct mo_padn* padding = (struct mo_padn*) b_ack->options;
    padding->type = 1; // Type code for PadN TLV
    padding->len = 2; // 2 octets to complete the 16 bytes
    memset(padding->pad, 0, 2);

    return msg;
}

uint8_t* create_binding_update() {
    uint8_t* msg = malloc(16);

    struct ip6_mh* mh = (struct ip6_mh*) msg;
    mh->ip6mh_proto = 59;
    mh->ip6mh_hdrlen = 1;
    mh->ip6mh_type = 5;
    mh->ip6mh_reserved = 0;
    mh->ip6mh_cksum = 0;

    struct mh_bu* bu = (struct mh_bu*) mh->payload;
    bu->sequence = htons(50);
    bu->status_bits = htons(BU_ACK_REQ | BU_HOME_REG);
    bu->lifetime = htons(16);
    
    struct mo_padn* padding = (struct mo_padn*) bu->options;
    padding->type = 1;
    padding->len = 2;
    memset(padding->pad, 0, 2);

    return msg;
}

int send_mo_msg(uint8_t* msg, int bytes, struct in6_addr* receiver, struct in6_addr* sender) {
    int sock = socket(AF_INET6, SOCK_RAW, IPPROTO_MH);
    if(sock < 0) {
        perror("Failed to create socket!");
        return -1;
    }

    int on = 1;
    if(setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(int)) < 0) {
        perror("Couldn't set option!");
        return -1;
    }

    int offset = 4;
    if(setsockopt(sock, IPPROTO_IPV6, IPV6_CHECKSUM, &offset, sizeof(int)) < 0) {
        perror("Couldn't set option!");
        return -1;
    }

    struct sockaddr_in6 host;
    host.sin6_family = AF_INET6;
    host.sin6_port = 0;
    memcpy(&host.sin6_addr, sender, sizeof(struct in6_addr));

    if (bind(sock, (struct sockaddr*) &host, sizeof(host)) == -1) {
        shutdown(sock, SHUT_RDWR);
        perror("Bind failed");
        return -1;
    }

    struct sockaddr_in6 s_addr;
    s_addr.sin6_family = AF_INET6;
    s_addr.sin6_port = 0;
    memcpy(&s_addr.sin6_addr, receiver, sizeof(struct in6_addr));

    ssize_t bytes_sent = sendto(sock, msg, bytes, 0, (struct sockaddr*) &s_addr, sizeof(s_addr));
    if(bytes_sent < bytes) {
        printf("Bytes sent is less than bytes received. %ld < %d\n", bytes_sent, bytes);
        shutdown(sock, SHUT_RDWR);
        return -1;
    }

    shutdown(sock, SHUT_RDWR);
    return 0;
}