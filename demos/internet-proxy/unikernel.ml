open Lwt.Infix
open Mirage_types_lwt
open Firewall_tree

module Main (C : CONSOLE) (N_A : NETWORK) (N_B : NETWORK) (E_A : ETHERNET) (E_B : ETHERNET) (A_A : ARP) (A_B : ARP) (I4_A : IPV4) (I4_B : IPV4) = struct
  let start c n_A n_B e_A e_B a_A a_B i4_A i4_B =
    Lwt.pick
      [ N_A.listen n_A ~header_size:Ethernet_wire.sizeof_ethernet
          (E_A.input
             ~arpv4:(A_A.input a_A)
             ~ipv4:(I4_A.input
                      ~tcp:(fun ~src:src_addr ~dst:dst_addr data ->
                          Lwt.return_unit
                        )
                      ~udp:(fun ~src:src_addr ~dst:dst_addr data -> Lwt.return_unit)
                      ~default:(fun ~proto ~src:_ ~dst:_ _data -> C.log c "ping on side A")
                      i4_A)
             ~ipv6:(fun _ -> Lwt.return_unit)
             e_A) >>= (fun _ -> Lwt.return_unit)
      ; N_B.listen n_B ~header_size:Ethernet_wire.sizeof_ethernet
          (E_B.input
             ~arpv4:(A_B.input a_B)
             ~ipv4:(I4_B.input
                      ~tcp:(fun ~src:src_addr ~dst:dst_addr data ->
                          Lwt.return_unit
                        )
                      ~udp:(fun ~src:src_addr ~dst:dst_addr data -> Lwt.return_unit)
                      ~default:(fun ~proto ~src:_ ~dst:_ _data -> C.log c "ping on side B")
                      i4_B)
             ~ipv6:(fun _ -> Lwt.return_unit)
             e_B) >>= (fun _ -> Lwt.return_unit)
      ]
end
