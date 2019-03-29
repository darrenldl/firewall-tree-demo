open Lwt.Infix
open Mirage_types_lwt
open Firewall_tree

module Main (C : CONSOLE) (N : NETWORK) (E : ETHERNET) (I4 : IPV4) (I6 : IPv6) = struct
  let start c n e i4 i6 =
    N.listen n ~header_size:Ethernet_wire.sizeof_ethernet
      (E.input
         ~arpv4:(fun _ -> Lwt.return_unit)
         ~ipv4:(I4.input
                  ~tcp:(fun ~src:src_addr ~dst:dst_addr data ->
                      
                      Lwt.return unit
                    )
                  ~udp:(fun _ -> Lwt.return unit)
                  ~default:(fun ~proto _ -> Lwt.return unit)
               i4)
         ~ipv6:(fun _ -> Lwt.return_unit)
         e)
    >>= (fun _ -> Lwt.return_unit)
end
