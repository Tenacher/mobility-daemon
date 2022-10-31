#ifndef TNL_C_H
#define TNL_C_H

#include <linux/in.h>

/*
* Finds the master INET6 address. Returned structure must be freed after use.
*/
struct in6_addr* find_master_addr();
/*
* Creates a tunnel between local and remote and adds the ip6 address tun_addr to the
* newly created interface.
*/
int create_tunnel(struct in6_addr* local, struct in6_addr* remote, struct in6_addr* tun_addr);

#endif