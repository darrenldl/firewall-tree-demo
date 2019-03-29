open Lwt.Infix
open Mirage_types_lwt
open Firewall_tree

module Main (C : CONSOLE) (N : NETWORK) (E : ETHERNET) (A : ARP) (I4 : IPV4) (I6 : IPV6) = struct
  let start c n e a i4 i6 =
    N.listen n ~header_size:Ethernet_wire.sizeof_ethernet
      (E.input
         ~arpv4:(A.input a)
         ~ipv4:(I4.input
                  ~tcp:(fun ~src:src_addr ~dst:dst_addr data ->
                      Lwt.return_unit
                    )
                  ~udp:(fun ~src:src_addr ~dst:dst_addr data -> Lwt.return_unit)
                  ~default:(fun ~proto ~src:_ ~dst:_ _data -> C.log c "ping")
               i4)
         ~ipv6:(fun _ -> Lwt.return_unit)
         e)
    >>= (fun _ -> Lwt.return_unit)
end
