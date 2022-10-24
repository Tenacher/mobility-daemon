#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

#include "sniffer.h"
#include "mobi-packets.h"
#include "tnl-c.h"

const char CLIENT_IPV6[] = "fd84:c300:ca02:76d2::2";

int main(int argc, char* argv[]) {
    if(argc != 2) {
        printf("The ip6 address of the HA needs to be supplied!\n");
        return -1;
    }

    printf("Received address: %s\n", argv[1]);
    struct in6_addr ha_addr;
    if(inet_pton(AF_INET6, argv[1], &ha_addr) < 1) {
        perror("Invalid ip6 address supplied!");
        return -1;
    }

    struct in6_addr* h_addr = find_master_addr();

    char buf[INET6_ADDRSTRLEN];
    printf("MASTER DEVICE: %s\n", inet_ntop(AF_INET6, h_addr, buf, INET6_ADDRSTRLEN));

    uint8_t* bu = create_binding_update();
    if(send_mo_msg(bu, 16, &ha_addr, h_addr) < 0) {
        perror("Couldn't send BU!");
        free(bu);
        return -1;
    }
    free(bu);
    free(h_addr);

    uint8_t msg[16]; //16bytes for B_ACK with padding
    if(sniff_for(B_ACK, msg, &ha_addr) < 0) {
        perror("Packet sniffing failed!");
        return -1;
    }

    struct ip6_mh* mh = (struct ip6_mh*) msg;
    struct mh_back* b_ack = (struct mh_back*) mh->payload;
    if(b_ack->status != BU_ACCEPTED) {
        printf("Binding Update was not accepted!\n");
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