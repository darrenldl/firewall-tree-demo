# Load balancing proxy

## Notes

You will need an extra device connected to the tap interface for this demo on top of the host machine. You can do this by booting up a LiveCD in a VM with network interface attached to the tap interface used below (tap100) for example.

## Build instructions

You need to pin the firewall-tree library at the moment as the library is not published to OPAM yet

You can do so with the following commands

```bash
opam pin add firewall-tree -k git https://gitlab.com/darrenldl/ocaml-firewall-tree.git
```

After installing `firewall-tree`, you can build the unikernel via

```bash
mirage configure -t hvt --ipv4=192.168.0.100
```

We're picking 192.168.0.100 for the network topology assumed in this demo

You also need to setup an appropriate network interface for running Solo5 based unikernels, you can read Solo5's network setup instructions [here](https://github.com/Solo5/solo5/blob/master/docs/building.md#setting-up)

We now build and run the unikernel with the following command

```bash
make depend # install other dependencies
make        # building the unikernel
./solo-hvt --net=tap100 proxy.hvt --dst-addrs=192.168.0.1
```

where tap100 is the interface established using Solo5's instructions

To communicate with the unikernel, we also need to add an IP to the tap interface on the host device. On Linux, this would look like

```bash
# ip addr add 192.168.0.254/24 dev tap100
```

adjust your firewall settings if necessary to allow input traffic from tap100.

The second device should have the 192.168.0.1 address

## Network

We've picked several IP addresses above, but we haven't explained the topology yet. Following shows the topology of the general case of this load balancing proxy

![network-general-case](network-general-case.png)

For n destination addresses specified through the `--dst-addrs` options, each incoming connection is mapped to one of the destionation address randomly

The library calls the unrestricted side "side A" and the load balanced side "side B". This naming convention is used for the translate functions provided by the library.

In this particular demo, we have the following topology

![Network demo case](network-demo-case.png)

Now you might be wondering how translation works when everything's on the same subnet

Normally translation requires two network interfaces, each on a different subnet. We are using the same subnet here ~~because I don't know how to use Xen and Solo5 only supports one interface atm~~ to demonstrate the flexibility of the firewall-tree library. The strategy used in this demo is just to identify everything with source address matching any of the dst-addrs as side B to A traffic, and everything else as side A to B traffic. The relevant fragment of the code is shown below

```ocaml
select_first_match
  [| Not (IPv4_src_addr_one_of dst_addrs), ... (* A -> B *)
   ; True, ... (* B -> A *)
  |]
```

the order is flipped for clarity, obviously you are free to match the side B to A case first.

With the network topology in mind, let's examine the firewall tree

## Firewall policy

As the name suggests, the library enables you to specify your firewall policy in a tree form

We show the graphical version of the policy below. The code version used in unikernel is annotated with more low-level details, but is otherwise equivalent in logic.

![Policy](firewall-policy.png)

To explain in text, essentially we want to reply to pings, but only every other ping packet, we block HTTP traffic very naively, and translate and forward all other TCP traffic to side B. Then for traffic from side B to A, we allow unconditionally.

## Testing it out

First we test the ping packet branch, if you do `ping 192.168.0.100`, you should see an output similar to the one shown below

```bash
$ ping 192.168.0.100
PING 192.168.0.100 (192.168.0.100) 56(84) bytes of data.
64 bytes from 192.168.0.100: icmp_seq=2 ttl=38 time=1.79 ms
64 bytes from 192.168.0.100: icmp_seq=4 ttl=38 time=0.444 ms
64 bytes from 192.168.0.100: icmp_seq=6 ttl=38 time=1.42 ms                                                                  
64 bytes from 192.168.0.100: icmp_seq=8 ttl=38 time=1.25 ms                                                                  
64 bytes from 192.168.0.100: icmp_seq=10 ttl=38 time=0.803 ms                                                                
64 bytes from 192.168.0.100: icmp_seq=12 ttl=38 time=1.29 ms
64 bytes from 192.168.0.100: icmp_seq=14 ttl=38 time=1.01 ms
64 bytes from 192.168.0.100: icmp_seq=16 ttl=38 time=0.899 ms
64 bytes from 192.168.0.100: icmp_seq=18 ttl=38 time=1.07 ms
^C
--- 192.168.0.100 ping statistics ---
18 packets transmitted, 9 received, 50% packet loss, time 242ms
rtt min/avg/max/mdev = 0.444/1.109/1.790/0.366 ms
```

And on the unikernel console, you should see an output similar to below

```bash
Received pdu
Layer 3 | IPv4     | src  192.168.0.254
                   | dst  192.168.0.100
Layer 3 | ICMPv4   | type Echo request, id 4a49, seq 17
                   | data
                   |      00000000: 0800 548d 4a49 0011 5fa8 a45c 0000 0000 T�JI_��\
                   |      00000001: 8a40 0c00 0000 0000 1011 1213 1415 1617  �@

                   |      00000002: 1819 1a1b 1c1d 1e1f 2021 2223 2425 2627  ▒▒!"#$%&'
                   |      00000003: 2829 2a2b 2c2d 2e2f 3031 3233 3435 3637  ()*+,-./01234567
Decision : Drop

Received pdu
Layer 3 | IPv4     | src  192.168.0.254
                   | dst  192.168.0.100
Layer 3 | ICMPv4   | type Echo request, id 4a49, seq 18
                   | data
                   |      00000000: 0800 0f29 4a49 0012 60a8 a45c 0000 0000 )JI`��\
                   |      00000001: cea3 0c00 0000 0000 1011 1213 1415 1617  Σ

                   |      00000002: 1819 1a1b 1c1d 1e1f 2021 2223 2425 2627  ▒▒!"#$%&'
                   |      00000003: 2829 2a2b 2c2d 2e2f 3031 3233 3435 3637  ()*+,-./01234567
Decision : Echo_reply
```


