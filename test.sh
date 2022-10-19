gcc tnl-c.c -o tnlc $(pkg-config --cflags --libs libnl-3.0 libnl-route-3.0)
./tnlc