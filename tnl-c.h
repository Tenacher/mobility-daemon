#ifndef TNL_C_H
#define TNL_C_H

int create_tunnel(struct nl_sock* socket, struct in6_addr* local, struct in6_addr* remote);

#endif