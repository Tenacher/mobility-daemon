gcc -o cl.out sniffer.h tnl-c.h mobi-packets.h tnl-c.c mobi-packets.c sniffer.c client.c $(pkg-config --cflags --libs libnl-3.0 libnl-route-3.0)
./cl.out