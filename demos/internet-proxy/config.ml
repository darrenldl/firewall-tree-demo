open Mirage

let packages = [
  package "ethernet";
  package "firewall-tree";
  package "tcpip";
]

let main =
  foreign
    ~packages
    "Unikernel.Main" (console @-> network @-> network @-> ethernet @-> ethernet @-> arpv4 @-> arpv4 @-> ipv4 @-> ipv4 @-> job)

let net_A = netif ~group:"side-A" "fjjidosjofnoisjos"
let ethif_A = etif net_A

let net_B = netif ~group:"side-B" "1fjdiso"
let ethif_B = etif net_B

let arp_A = arp ethif_A
let arp_B = arp ethif_B

let ipv4_A =
  let addr = Ipaddr.V4.make 10 0 0 10 in
  let config = {
    network = (Ipaddr.V4.Prefix.make 24 addr, addr);
    gateway = None;
  } in
  create_ipv4 ~config ethif_A arp_A

let ipv4_B =
  let addr = Ipaddr.V4.make 11 0 0 10 in
  let config = {
    network = (Ipaddr.V4.Prefix.make 24 addr, addr);
    gateway = None;
  } in
  create_ipv4 ~config ethif_B arp_B

let () =
  register "ft-demo0" [ main $ default_console $ net_A $ net_B $ ethif_A $ ethif_B $ arp_A $ arp_B $ ipv4_A $ ipv4_B ]
