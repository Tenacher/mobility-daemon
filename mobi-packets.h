#ifndef MOBI_PACKETS_H
#define MOBI_PACKETS_H

#include <stdint.h>
#include <linux/in6.h>

typedef enum {
    BU = 5, // Binding Update message MH Type
    B_ACK = 6 // Binding Acknowledgement MH Type
} MobilityHeaderType;

static const uint8_t BU_ACK_REQ = (1 << 7); // Binding Acknowledgement requested
static const uint8_t BU_HOME_REG = (1 << 6); // Home Registration message

static const uint8_t BU_ACCEPTED = 0; // Binding Update accepted status

struct ip6_mh {
	uint8_t	ip6mh_proto;
	uint8_t	ip6mh_hdrlen;
	uint8_t	ip6mh_type;
	uint8_t	ip6mh_reserved;
	uint16_t ip6mh_cksum;
    uint8_t payload[];
};

struct mh_bu {
    uint16_t sequence;
    uint16_t status_bits;
    uint16_t lifetime;
    uint8_t options[];
};

struct mh_back {
    uint8_t status;
    uint8_t reserved;
    uint16_t sequence;
    uint16_t lifetime;
    uint8_t options[];
};

struct mo_padn {
    uint8_t type;
    uint8_t len;
    uint8_t pad[];
};

/*
* Returns a byte pointer to the created message.
* Needs to be freed after use.
*/
uint8_t* create_binding_ack(uint16_t sequence);

/*
* Returns a byte pointer to the created message.
* Needs to be freed after use.
*/
uint8_t* create_binding_update();

/*
* Sends the specified mobility message that is bytes long.
* Sender address is required to bind to a local address.
*/
int send_mo_msg(uint8_t* msg, int bytes, struct in6_addr* receiver, struct in6_addr* sender);

#endif