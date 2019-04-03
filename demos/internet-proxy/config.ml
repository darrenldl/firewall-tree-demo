open Mirage
open Mirage_impl_arpv4
open Mirage_impl_network
open Mirage_impl_ethernet
open Mirage_impl_ip
open Mirage_impl_icmp
open Mirage_impl_tcp
open Mirage_impl_resolver
open Mirage_impl_conduit

let key_dst_addrs =
  let doc = Key.Arg.info ~doc:"Destination IPv4 addresses to be used for load balancing" ["dst-addrs"] in
  Key.(create "dst_addrs" Arg.(required (list ipv4_address) doc))

let packages = [
  package "ethernet";
  package "firewall-tree";
  package "tcpip";
  package "dns";
  package "mirage-dns";
]

let main =
  foreign
    ~keys:[Key.abstract key_dst_addrs]
    ~packages
    "Unikernel.Main" (console @-> mclock @-> network @-> ethernet @-> arpv4 @-> ipv4 @-> icmpv4 @-> tcp @-> job)

let net = default_network
let ethif = etif net

let arp = arp ethif

(* let ipv4 =
 *   let addr = Ipaddr.V4.make 10 0 0 10 in
 *   let config = {
 *     network = (Ipaddr.V4.Prefix.make 24 addr, addr);
 *     gateway = None;
 *   } in
 *   create_ipv4 ~config ethif arp *)

let ipv4 =
  create_ipv4 ethif arp

let tcp = direct_tcp ipv4

let icmpv4 = direct_icmpv4 ipv4

let () =
  register "proxy" ~packages [ main $ default_console $ default_monotonic_clock $ net $ ethif $ arp $ ipv4 $ icmpv4 $ tcp ]
