open Lwt.Infix
open Mirage_types_lwt
open Firewall_tree

module Main (C : CONSOLE) (N : NETWORK) = struct
  let start c n =
    N.listen n ~header_size:Ethernet_wire.sizeof_ethernet
      (fun _ -> C.log c "Testing")
end
