# Load balancing proxy

## Notes

You will need an extra device for a clearer demo. You can do this by booting up a LiveCD in a VM with network interface attached to the tap interface used below (tap100).

However, the demo also works if you only have the host machine available. The instructions for single device setup are attached next to the original instructions when applicable.

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

adjust your firewall settings if necessary to allow input traffic from tap100

(If your setup is a single host device, replace `192.168.0.254` with `192.168.0.1` in the above command)

## Network

We've picked several IP addresses above, but we haven't explained the topology yet. Following shows the topology of the general case of this load balancing proxy

![network-general-case](network-general-case.png)

For n destination addresses specified through the `--dst-addrs` options, each incoming connection is mapped to one of the destionation address randomly
