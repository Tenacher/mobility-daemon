# mobility-daemon
A proof-of-concept implementation of MIPv6.

## Description
The repository consists of a Home Agent and client main module. The former can be found at mobility-daemon.c, the latter under client.c. Both instances can be compiled natively using the other provided modules, the only external dependency being libnl, which can be found at:
```
https://www.infradead.org/~tgr/libnl/
```

## Compilation
Compilation of the modules is normally done by docker build using the desired configuration provided in their respective Dockerfiles. An example command that accomplishes this is the following.
```
docker build -t myrepo/my-ha:latest -f Dockerfile.daemon .
```

## How it works
We can deploy the compiled container images in an IPv6 Kubernetes environment. IPv6 networking context is important as this program is not compatible with IPv4.
One thing we need to be aware of is that the containers require ```NET_ADMIN``` capability which can be added using the securityContext tag in the pod template file.

We can try out the client by simply supplying the ```cl.out``` program with the IPv6 address of the Home Agent and running it with root priviliges.
