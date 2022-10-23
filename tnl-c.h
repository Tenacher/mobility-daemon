#ifndef TNL_C_H
#define TNL_C_H

#include <linux/in.h>

struct in6_addr* find_master_addr();
int create_tunnel(struct in6_addr* local, struct in6_addr* remote, struct in6_addr* tun_addr);

#endif