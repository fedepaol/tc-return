# EBPF TC egress redirect example

This is a sample application where we rely on ebpf to set the next hop for egress traffic based on the
source address of a given packet.

## How to validate

Under the `validate` folder there's a docker-compose setup which will start the following setup:

```
             │
             │
             │
             │10.111.220.11
┌────────────┴─────┐       ┌──────────────────┐        ┌────────────────┐
│                  │       │                  │        │                │
│                  │       │                  │        │                │
│                  │       │                  │        │                │
│                  │       │                  │        │                │
│                  ├───────┤                  ├────────┤                │
│                  │   ▲   │                  │    ▲   │                │
│                  │   │   │                  │    │   │                │
│                  │   │   │                  │    │   │                │
│ server           │   │   │ router           │    │   │ client         │
└──────────────────┘   │   └──────────────────┘    │   └────────────────┘

                10.111.221.0/24             10.111.222.0/24
```

The server's default gateway is via the 10.111.20.11 interface.

The `192.168.1.5` address is added to the `server`'s `lo` interface.

Run a listener on the `server`, such as `nc -l 30100` and try to reach the listener from the `client`, and then try to
reach the server by running `nc 192.168.1.5` on the `client`.

The traffic coming from the `client` container can reach the server because of the routes added on the `router` container.

When the `server` replies, there is no routing in place to allow the traffic reach the router, so the traffic
would exit via the default gateway, leading to asymmetric routing (and in this case, to the reply to be lost).

## The EBPF program

Running the binary will add an ebpf program to the default gateway interface that leverages the `bpf_redirect_neigh`
helper to redirect the traffic via another interface.

The poc leverages the go ebpf library and is split in two functions:

```
func attachFilter(attachTo string, program *ebpf.Program) error {
```

which is used to attach the bpf program to the given interface.

and 

```
func enableRedirect(src, nextHop net.IP, interfaceName string, ebpfMap *ebpf.Map) error {
```

were we expose the a way to set a new nexthop / interface based on the source address of the traffic
(in this example we pass `192.168.1.5` as the src ip, and `eth1` and `10.111.221.21` as the interface / next hop).


