#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/if.h>
#include <netlink/netlink.h>
#include <netlink/cache.h>
#include <netlink/route/link.h>
#include <netlink/route/addr.h>
#include <netlink/route/link/ip6tnl.h>

const int ERROR = -1;
const char LOCAL_IPv6[] = "fd84:c300:ca02:76d2::1";
const char REMOTE_IPv6[] = "fd84:c300:ca02:76d2::2";
const char TUN_NAME[] = "ip6tun0";

void free_structures(struct nl_sock* sock, struct rtnl_link* tunnel) {
    rtnl_link_put(tunnel);
    nl_close(sock);
    nl_socket_free(sock);
}

/*
* Finds master device. Returned structure needs to be freed.
*/
int find_master_device(struct nl_sock* socket) {
    struct nl_cache* link_cache = NULL;
    if(rtnl_link_alloc_cache(socket, AF_UNSPEC, &link_cache) < 0) {
        perror("Could not allocate link cache!");
        return ERROR;
    }

    int eth0 = 0;
    if (!(eth0 = rtnl_link_name2i(link_cache, "enp0s3"))) {
        perror("Could not find master device!");
        nl_cache_put(link_cache);
        return ERROR;
    }

    nl_cache_put(link_cache);
    return eth0;
}

int main() {
    struct nl_sock* socket = nl_socket_alloc(); //Setting up important structures
    struct rtnl_link* tunnel = rtnl_link_ip6_tnl_alloc();
    nl_connect(socket, NETLINK_ROUTE);

    int eth0 = find_master_device(socket);
    if(eth0 < 0) {
        perror("Error finding master device!");
        free_structures(socket, tunnel);
        return ERROR;
    }

    rtnl_link_set_name(tunnel, TUN_NAME);
    rtnl_link_set_link(tunnel, eth0); //Set default link as the master device
    //rtnl_link_set_flags(tunnel, IFF_UP);
    rtnl_link_ip6_tnl_set_proto(tunnel, IPPROTO_IPV6);

    //Build required addresses
    struct in6_addr* loc = malloc(sizeof(struct in6_addr));
    struct in6_addr* rem = malloc(sizeof(struct in6_addr));
    inet_pton(AF_INET6, LOCAL_IPv6, loc);
    inet_pton(AF_INET6, REMOTE_IPv6, rem);

    rtnl_link_ip6_tnl_set_local(tunnel, loc);
    rtnl_link_ip6_tnl_set_remote(tunnel, rem);

    if(rtnl_link_add(socket, tunnel, NLM_F_CREATE) < 0) {
        perror("Could not create link!");
        free_structures(socket, tunnel);
        free(loc);
        free(rem);
        return ERROR;
    }

    free_structures(socket, tunnel);
    free(loc);
    free(rem);

    printf("Tunnel successfully created!");
    return 0;
}



