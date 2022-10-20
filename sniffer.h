#ifndef SNIFFER
#define SNIFFER

typedef enum {
    BU,
    B_ACK
} MobilityHeaderType;

/*
*  Wait for a packet of specified type,
*  then return it via the buffer.
*/
int sniff_for(MobilityHeaderType type, char* buffer);

#endif