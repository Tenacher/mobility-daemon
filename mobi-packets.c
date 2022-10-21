#include "mobi-packets.h"

#include <stdlib.h>
#include <string.h>

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
    b_ack->sequence = sequence; // RFC: same as BU sequence
    b_ack->lifetime = 16; // in units of 4 seconds -> 16 lifetime = 16*4 sec = 64 sec

    struct mo_padn* padding = (struct mo_padn*) b_ack->options;
    padding->type = 1; // Type code for PadN TLV
    padding->len = 2; // 2 octets to complete the 16 bytes
    memset(padding->pad, 0, 2);

    return msg;
}


