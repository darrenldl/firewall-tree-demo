open Mirage

let packages = [
  package "ethernet";
  package "firewall-tree";
  package "tcpip";
]

let main =
  foreign
    ~packages
    "Unikernel.Main" (console @-> network @-> ethernet @-> ipv4 @-> ipv6 @-> job)

let net = default_network
let ethif = etif net

let ipv4 =
  let addr = Ipaddr.V4.make 10 0 0 10 in
  let config = {
    network = (Ipaddr.V4.Prefix.make 24 addr, addr);
    gateway = None;
  } in
  create_ipv4 ethif (arp ethif)

let ipv6 =
  let config = {
    addresses = [];
    netmasks  = [];
    gateways  = [];
  } in
  create_ipv6 ethif config

let () =
  register "ft-demo0" [ main $ default_console $ default_network $ ethif $ ipv4 $ ipv6 ]
