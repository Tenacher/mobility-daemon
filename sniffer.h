#ifndef SNIFFER_H
#define SNIFFER_H

#include <stdint.h>
#include <linux/in6.h>

#include "mobi-packets.h"

/*
*  Wait for a packet of specified type,
*  then return it via the buffer.
*/
int sniff_for(MobilityHeaderType mh_type, uint8_t* buffer, struct in6_addr* source);

#endif