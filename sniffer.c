#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/icmpv6.h>
#include <pcap.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>

#include "sniffer.h"

const int PKT_LEN = 20000;

static inline size_t to_bytes(uint8_t mh_hdrlen) {
    return (mh_hdrlen + 1) * 8; // https://www.rfc-editor.org/rfc/rfc6275 for more information about the conversion
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer);

struct response {
    MobilityHeaderType mh_type;
    uint8_t* buffer;
    struct in6_addr* source;
    pcap_t* handle;
};

int sniff_for(MobilityHeaderType mh_type, uint8_t* buffer, struct in6_addr* source) {
    const char *dev = "eth0";
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_create(dev, errbuf);
    if(handle == NULL) {
        printf("%s", errbuf);
        return -1;
    }

    if(pcap_set_timeout(handle, 100) != 0) {
        printf("Couldn't set timeout");
        return -1;
    };

    if(pcap_activate(handle) != 0) {
        printf("Couldn't activate");
        pcap_perror(handle, "");
        return -1;
    }

    struct bpf_program pf;
    if(pcap_compile(handle, &pf, "ip6 proto 135", 1, PCAP_NETMASK_UNKNOWN) != 0) {
        printf("Couldn't compile filter expression!");
        pcap_perror(handle, "");
        return -1;
    }

    pcap_setfilter(handle, &pf);

    struct response resp;
    resp.mh_type = mh_type;
    resp.buffer = buffer;
    resp.source = source;
    resp.handle = handle;

    printf("Entering main loop\n");
    printf("Mh_type: %d\n", mh_type);
    fflush(stdout);
    pcap_loop(handle, -1, process_packet, (u_char*) &resp);

    pcap_close(handle);
    return 0;
}


void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    struct response* resp = (struct response*) args;
    struct ip6_hdr* ip6hdr = (struct ip6_hdr*) (buffer + sizeof(struct ethhdr));
    struct ip6_mh* mh = (struct ip6_mh*) (buffer + sizeof(struct ethhdr) + sizeof(struct ip6_hdr));

    printf("Proto: %d, MH_type: %d\n", mh->ip6mh_proto, mh->ip6mh_type);
    fflush(stdout);

    if(mh->ip6mh_type == resp->mh_type) {
        memcpy(resp->buffer, mh, to_bytes(mh->ip6mh_hdrlen));
        memcpy(resp->source, &ip6hdr->ip6_src, sizeof(struct in6_addr));
        pcap_breakloop(resp->handle);
        return;
    }

    return;
}
