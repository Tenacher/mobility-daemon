#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

#include "sniffer.h"
#include "mobi-packets.h"
#include "tnl-c.h"

const char HA_IPV6[] = "fd84:c300:ca02:76d2::1";

int main() {
    uint8_t msg[16]; //16bytes for BU with padding
    struct in6_addr CoA;

    if(sniff_for(BU, msg, &CoA) < 0) {
        perror("Packet sniffing failed!");
        return -1;
    }

    struct in6_addr tun_addr; 
    inet_pton(AF_INET6, HA_IPV6, &tun_addr);

    struct in6_addr* local = find_master_addr();
    if(create_tunnel(local, &CoA, &tun_addr) < 0) {
        perror("Couldn't create tunnel!");
        return -1;
    }

    struct ip6_mh* mh = (struct ip6_mh*) msg;
    struct mh_bu* bu = (struct mh_bu*) mh->payload;

    uint8_t* b_ack = create_binding_ack(bu->sequence);

    if(send_mo_msg(b_ack, 16, &CoA) < 0) {
        perror("Couldn't send ACK!");
        return -1;
    }

    free(b_ack);
    return 0;
}