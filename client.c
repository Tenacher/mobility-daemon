#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "sniffer.h"
#include "mobi-packets.h"
#include "tnl-c.h"

const char CLIENT_IPV6[] = "fd84:c300:ca02:76d2::2";

int send_update(uint8_t* msg, int bytes, struct in6_addr* receiver) {
    int sock = socket(AF_INET6, SOCK_RAW, IPPROTO_MH);
    if(sock < 0) {
        perror("Failed to create socket!");
        return -1;
    }

    struct sockaddr_in6 s_addr;
    s_addr.sin6_family = AF_INET6;
    memcpy(&s_addr.sin6_addr, receiver, sizeof(struct in6_addr));
    ssize_t bytes_sent = sendto(sock, msg, bytes, 0, &s_addr, sizeof(struct sockaddr));

    if(bytes_sent < bytes) {
        printf("Bytes sent is less than bytes received.");
        shutdown(sock, SHUT_RDWR);
        return -1;
    }

    shutdown(sock, SHUT_RDWR);
    return 0;
}

int main() {
    uint8_t msg[16]; //16bytes for B_ACK with padding
    struct in6_addr ha_addr;

    uint8_t* bu = create_binding_update();

    if(send_update(bu, 16, &ha_addr) < 0) {
        perror("Couldn't send ACK!");
        free(bu);
        return -1;
    }

    free(bu);

    if(sniff_for(B_ACK, msg, &ha_addr) < 0) {
        perror("Packet sniffing failed!");
        return -1;
    }

    struct ip6_mh* mh = (struct ip6_mh*) msg;
    struct mh_back* b_ack = (struct mh_back*) mh->payload;

    if(b_ack->status != BU_ACCEPTED) {
        printf("Binding Update was not accepted!");
        return 0;
    }

    struct in6_addr tun_addr; 
    inet_pton(AF_INET6, CLIENT_IPV6, &tun_addr);

    struct in6_addr* local = find_master_addr();
    if(create_tunnel(local, &ha_addr, &tun_addr) < 0) {
        perror("Couldn't create tunnel!");
        return -1;
    }

    return 0;
}