open Lwt.Infix
open Mirage_types_lwt

module Main
    (C : CONSOLE)
    (MClock : MCLOCK)
    (N : NETWORK)
    (E : ETHERNET)
    (A : ARP)
    (I4 : IPV4)
    (ICMP4 : ICMPV4)
    (T : TCP) =
struct
  (* we define our environment implementation (or tree base) for the firewall tree *)
  module Base = struct
    let id x = x

    (* decision can be arbitrarily defined, and is part of the outcome

       we only care about three decisions for now, we can always add more later
    *)
    type decision = Drop | Forward | Echo_reply

    (* this is just for the firewall-tree library to distinguish between
       interfaces

       we only have one interface, so we use a single variant here
    *)
    type netif = Net0

    (* firewall-tree needs access to current time for timed out entries
       cleanup in Lookup_table, which is used for connection tracking,
       translation etc
    *)
    let cur_time_ms () = Int64.div (MClock.elapsed_ns ()) 1000L

    (* we don't care about ethernet frames, use dummy implementation *)
    module Ether = Firewall_tree.Mock_tree_base.Ether

    module IPv4 = struct
      type ipv4_addr = Ipaddr.V4.t

      (* `header_can_be_modified_inplace` is used by update_header functions
         provided by firewall-tree to determine whether to update header
         in-place or return a new header through make_header

         in-place modification for headers is mainly useful for when header
         is a singular chunk of data
      *)
      let header_can_be_modified_inplace = false

      type ipv4_header = {src_addr: ipv4_addr; dst_addr: ipv4_addr}

      type ipv4_payload_raw = Cstruct.t

      let compare_ipv4_addr = Ipaddr.V4.compare

      let ipv4_addr_to_byte_string = Ipaddr.V4.to_bytes

      let byte_string_to_ipv4_addr = Ipaddr.V4.of_bytes_exn

      let ipv4_header_to_src_addr r = r.src_addr

      let ipv4_header_to_dst_addr r = r.dst_addr

      let make_ipv4_header ~src_addr ~dst_addr = {src_addr; dst_addr}

      (* since we set `header_can_be_modified_inplace` to false, the
         following update header functions will not be invoked, so we can
         just leave a dummy implementation here
      *)
      let update_ipv4_header_inplace ~src_addr:_ ~dst_addr:_ _header = ()

      let update_ipv4_header_inplace_byte_string ~src_addr:_ ~dst_addr:_
          _header =
        ()

      let ipv4_payload_raw_to_byte_string c = Cstruct.to_string c

      let byte_string_to_ipv4_payload_raw s = Cstruct.of_string s
    end

    module IPv6 = Firewall_tree.Mock_tree_base.IPv6

    module ICMPv4 = struct
      open IPv4

      type icmpv4_type =
        | ICMPv4_Echo_reply of {id: string; seq: int}
        | ICMPv4_Destination_unreachable
        | ICMPv4_Source_quench
        | ICMPv4_Redirect
        | ICMPv4_Echo_request of {id: string; seq: int}
        | ICMPv4_Time_exceeded
        | ICMPv4_Parameter_problem
        | ICMPv4_Timestamp_request of {id: string; seq: int}
        | ICMPv4_Timestamp_reply of {id: string; seq: int}
        | ICMPv4_Information_request of {id: string; seq: int}
        | ICMPv4_Information_reply of {id: string; seq: int}

      type icmpv4_header =
        {ty: icmpv4_type}

      type icmpv4_payload_raw = Cstruct.t

      let header_can_be_modified_inplace = false

      let icmpv4_header_to_icmpv4_type header = header.ty

      let make_icmpv4_header ty = {ty}

      let update_icmpv4_header_inplace _ty _header = ()

      let update_icmpv4_header_inplace_byte_string _ty
          _header =
        ()

      let icmpv4_payload_raw_to_byte_string c = Cstruct.to_string c

      let byte_string_to_icmpv4_payload_raw s = Cstruct.of_string s
    end

    module ICMPv6 = Firewall_tree.Mock_tree_base.ICMPv6

    module TCP = struct
      type tcp_port = int

      type tcp_header =
        { src_port: tcp_port
        ; dst_port: tcp_port
        ; ack: bool
        ; rst: bool
        ; syn: bool
        ; fin: bool }

      type tcp_payload_raw = Cstruct.t

      let header_can_be_modified_inplace = false

      let compare_tcp_port = compare

      let tcp_header_to_src_port header = header.src_port

      let tcp_header_to_dst_port header = header.dst_port

      let tcp_header_to_ack_flag header = header.ack

      let tcp_header_to_rst_flag header = header.rst

      let tcp_header_to_syn_flag header = header.syn

      let tcp_header_to_fin_flag header = header.fin

      let make_tcp_header ~src_port ~dst_port ~ack ~rst ~syn ~fin =
        {src_port; dst_port; ack; rst; syn; fin}

      let update_tcp_header_inplace ~src_port:_ ~dst_port:_ ~ack:_ ~rst:_
          ~syn:_ ~fin:_ _header =
        ()

      let tcp_payload_raw_to_byte_string c = Cstruct.to_string c

      let byte_string_to_tcp_payload_raw s = Cstruct.of_string s
    end

    module UDP = struct
      type udp_port = int

      type udp_header = {src_port: udp_port; dst_port: udp_port}

      type udp_payload_raw = Cstruct.t

      let header_can_be_modified_inplace = false

      let compare_udp_port = compare

      let udp_header_to_src_port header = header.src_port

      let udp_header_to_dst_port header = header.dst_port

      let make_udp_header ~src_port ~dst_port = {src_port; dst_port}

      let update_udp_header_inplace ~src_port:_ ~dst_port:_ _header = ()

      let udp_payload_raw_to_byte_string c = Cstruct.to_string c

      let byte_string_to_udp_payload_raw s = Cstruct.of_string s
    end
  end

  (* we feed the environment implementation to the functor to get our tree *)
  module FT = Firewall_tree.Make (Base)
  (* we also want to selectors provided by firewall-tree *)
  module Selectors = Firewall_tree.Selectors.Make (FT)

  (* we define some helpers to help wrapping things into processable types
     for the tree
  *)
  module Helpers = struct
    let data_to_tcp_header data =
      let src_port = Tcp.Tcp_wire.get_tcp_src_port data in
      let dst_port = Tcp.Tcp_wire.get_tcp_dst_port data in
      let ack = Tcp.Tcp_wire.get_ack data in
      let rst = Tcp.Tcp_wire.get_rst data in
      let syn = Tcp.Tcp_wire.get_syn data in
      let fin = Tcp.Tcp_wire.get_fin data in
      FT.TCP.make_tcp_header ~src_port ~dst_port ~ack ~rst ~syn ~fin

    let data_to_tcp_pdu data =
      let open FT.PDU in
      let header = data_to_tcp_header data in
      let data_offset = Tcp.Tcp_wire.get_data_offset data in
      let data_raw = Cstruct.shift data data_offset in
      TCP (TCP_pdu {header; payload= TCP_payload_raw data_raw})

    let data_to_udp_header data =
      let src_port = Udp_wire.get_udp_source_port data in
      let dst_port = Udp_wire.get_udp_dest_port data in
      FT.UDP.make_udp_header ~src_port ~dst_port

    let data_to_udp_pdu data =
      let open FT.PDU in
      let header = data_to_udp_header data in
      let data_offset = 8 in
      let data_raw = Cstruct.shift data data_offset in
      UDP (UDP_pdu {header; payload= UDP_payload_raw data_raw})

    let get_icmpv4_ty data : FT.ICMPv4.icmpv4_type option =
      let open FT.ICMPv4 in
      let get_icmpv4_id_seq data : string * int =
        let id = Printf.sprintf "%02X" (Icmpv4_wire.get_icmpv4_id data) in
        let seq = Icmpv4_wire.get_icmpv4_seq data in
        (id, seq)
      in
      match Icmpv4_wire.get_icmpv4_ty data |> Icmpv4_wire.int_to_ty with
      | None ->
        None
      | Some ty ->
        Some
          ( match ty with
            | Echo_reply ->
              let id, seq = get_icmpv4_id_seq data in
              ICMPv4_Echo_reply {id; seq}
            | Destination_unreachable ->
              ICMPv4_Destination_unreachable
            | Source_quench ->
              ICMPv4_Source_quench
            | Redirect ->
              ICMPv4_Redirect
            | Echo_request ->
              let id, seq = get_icmpv4_id_seq data in
              ICMPv4_Echo_request {id; seq}
            | Time_exceeded ->
              ICMPv4_Time_exceeded
            | Parameter_problem ->
              ICMPv4_Parameter_problem
            | Timestamp_request ->
              let id, seq = get_icmpv4_id_seq data in
              ICMPv4_Timestamp_request {id; seq}
            | Timestamp_reply ->
              let id, seq = get_icmpv4_id_seq data in
              ICMPv4_Timestamp_reply {id; seq}
            | Information_request ->
              let id, seq = get_icmpv4_id_seq data in
              ICMPv4_Information_request {id; seq}
            | Information_reply ->
              let id, seq = get_icmpv4_id_seq data in
              ICMPv4_Information_reply {id; seq} )
  end

  (* we don't actually need Routing Logic Unit (RLU) here,
     and they are not fully functional yet,
     but they are mandatory for the decide function as
     RLU is necessary to determine egress network interface
     and next-hop address etc, which may be used in the policy
  *)
  let rlu_ipv4 = FT.RLU_IPv4.make ()
  let rlu_ipv6 = FT.RLU_IPv6.make ()

  (* finally we define our policy through firewall tree

     see the diagram for a clearer representation
  *)
  let ftree =
    let open FT in
    let open Pred in
    let tracker = Conn_track.make ~max_conn:1000 ~init_size:10 ~timeout_ms:30_000L in
    Start
      { default = Drop
      ; next =
          Select
            (Selectors.make_select_first_match
               (* this selects the first branch with a satisfied predicate

                  we use the same tracker for all predicates so they share
                  the same information, which is what we want

                  `Invalid` connection is implicitly dropped

                  selectors can drop a pdu and result in default decision
                  by picking a negative or out of bound branch index
               *)
               [| Conn_state_eq { tracker; target_state = Conn_track.New },
                  Select (
                    Selectors.make_select_first_match
                      [|                    |]
                  )
                ; Conn_state_eq { tracker; target_state = Conn_track.Established },
                  Select (
                    Selectors.make_select_first_match
                      [|                    |]
                  )
               |]
            )
      }

  let start c m n e a i4 icmp4 tcp =
    (* make a wrapper to call FT.decide and react to outcome *)
    let react pdu =
      match FT.decide ftree ~src_netif:Net0 rlu_ipv4 rlu_ipv6 pdu with
      | Drop, _ ->
          C.log c "Drop"
      | Forward, pdu ->
          C.log c "Forward"
      | Echo_reply, _ -> (
          C.log c "Echo_reply"
          <&>
          match FT.PDU_to.ipv4_header pdu, FT.PDU_to.icmpv4_pkt pdu with
          | Some ipv4_header, Some (ICMPv4_pkt {header; payload}) ->
              let src = FT.IPv4.ipv4_header_to_src_addr ipv4_header in
              let dst = FT.IPv4.ipv4_header_to_dst_addr ipv4_header in
              let (ICMPv4_payload_raw data) = payload in
              ICMP4.input icmp4 ~src ~dst data
          | _ -> Lwt.return_unit
        )
    in
    N.listen n ~header_size:Ethernet_wire.sizeof_ethernet
      (E.input ~arpv4:(A.input a)
         ~ipv4:
           (I4.input
              ~tcp:(fun ~src:src_addr ~dst:dst_addr data ->
                let open FT.PDU in
                let header = FT.IPv4.make_ipv4_header ~src_addr ~dst_addr in
                let tcp_pdu = Helpers.data_to_tcp_pdu data in
                let pdu =
                  Layer3
                    (IPv4
                       (IPv4_pkt {header; payload= IPv4_payload_encap tcp_pdu}))
                in
                react pdu )
              ~udp:(fun ~src:src_addr ~dst:dst_addr data ->
                let open FT.PDU in
                let header = FT.IPv4.make_ipv4_header ~src_addr ~dst_addr in
                let udp_pdu = Helpers.data_to_udp_pdu data in
                let pdu =
                  Layer3
                    (IPv4
                       (IPv4_pkt {header; payload= IPv4_payload_encap udp_pdu}))
                in
                react pdu )
              ~default:(fun ~proto ~src:src_addr ~dst:dst_addr data ->
                let open FT.PDU in
                if proto = 1 then
                  (* only care about ICMP *)
                  match Helpers.get_icmpv4_ty data with
                  | None ->
                      Lwt.return_unit
                  | Some ty ->
                      let ipv4_header =
                        FT.IPv4.make_ipv4_header ~src_addr ~dst_addr
                      in
                      let icmpv4_pkt =
                        let header =
                          FT.ICMPv4.make_icmpv4_header ty
                        in
                        let payload =
                          ICMPv4_payload_raw data
                        in
                        ICMPv4_pkt {header; payload}
                      in
                      let pdu =
                        Layer3
                          (IPv4
                             (IPv4_pkt
                                {header  = ipv4_header;
                                 payload = IPv4_payload_icmp icmpv4_pkt}))
                      in
                      react pdu
                else Lwt.return_unit )
              i4)
         ~ipv6:(fun _ -> Lwt.return_unit)
         e)
end
