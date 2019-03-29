open Mirage

let packages = [
  package "ethernet";
  package "firewall-tree";
  package "tcpip";
]

let main =
  foreign
    ~packages
    "Unikernel.Main" (console @-> mclock @-> network @-> ethernet @-> arpv4 @-> ipv4 @-> tcp @-> job)

let net = default_network
let ethif = etif net

let arp = arp ethif

let ipv4 =
  let addr = Ipaddr.V4.make 10 0 0 10 in
  let config = {
    network = (Ipaddr.V4.Prefix.make 24 addr, addr);
    gateway = None;
  } in
  create_ipv4 ~config ethif arp

let ipv4 =
  create_ipv4 ethif arp

let stack = generic_stackv4 default_network

let tcp = direct_tcp ipv4

let () =
  register "proxy" ~packages [ main $ default_console $ default_monotonic_clock $ net $ ethif $ arp $ ipv4 $ tcp ]
