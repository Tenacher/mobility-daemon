#ifndef SNIFFER_H
#define SNIFFER_H

#include "mobi-packets.h"

/*
*  Wait for a packet of specified type,
*  then return it via the buffer.
*/
int sniff_for(MobilityHeaderType mh_type, char* buffer, struct in6_addr* source);

#endif