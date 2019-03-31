open Lwt.Infix
open Mirage_types_lwt

module Main (C : CONSOLE) (MClock: MCLOCK) (N : NETWORK) (E : ETHERNET) (A : ARP) (I4 : IPV4) (ICMP4 : ICMPV4) (T : TCP) = struct
  module Base = struct
    let id x = x

    type decision = Drop | Forward | Echo_reply

    type netif = Net0

    let cur_time_ms () = Int64.div (MClock.elapsed_ns ()) 1000L

    (* we don't care about ethernet frames, use dummy implementation *)
    module Ether = Firewall_tree.Mock_tree_base.Ether

    module IPv4 = struct
      type ipv4_addr = Ipaddr.V4.t

      let header_can_be_modified_inplace = false

      type ipv4_header = {
        src_addr : ipv4_addr;
        dst_addr : ipv4_addr;
      }

      type ipv4_payload_raw = Cstruct.t

      let compare_ipv4_addr = Ipaddr.V4.compare

      let ipv4_addr_to_byte_string = Ipaddr.V4.to_bytes

      let byte_string_to_ipv4_addr = Ipaddr.V4.of_bytes_exn

      let ipv4_header_to_src_addr r = r.src_addr
      let ipv4_header_to_dst_addr r = r.dst_addr

      let make_ipv4_header ~src_addr ~dst_addr = { src_addr; dst_addr }

      let update_ipv4_header_inplace ~src_addr:_ ~dst_addr:_ _header = ()

      let update_ipv4_header_inplace_byte_string ~src_addr:_ ~dst_addr:_ _header =
        ()

      let ipv4_payload_raw_to_byte_string c = Cstruct.to_string c
      let byte_string_to_ipv4_payload_raw s = Cstruct.of_string s
    end

    module IPv6 = Firewall_tree.Mock_tree_base.IPv6

    module ICMPv4 = struct
      open IPv4

      type icmpv4_type =
        | ICMPv4_Echo_reply of {id : string; seq : int}
        | ICMPv4_Destination_unreachable
        | ICMPv4_Source_quench
        | ICMPv4_Redirect
        | ICMPv4_Echo_request of {id : string; seq : int}
        | ICMPv4_Time_exceeded
        | ICMPv4_Parameter_problem
        | ICMPv4_Timestamp_request of {id : string; seq : int}
        | ICMPv4_Timestamp_reply of {id : string; seq : int}
        | ICMPv4_Information_request of {id : string; seq : int}
        | ICMPv4_Information_reply of {id : string; seq : int}

      type icmpv4_header =
        {src_addr : ipv4_addr; dst_addr : ipv4_addr; ty : icmpv4_type}

      type icmpv4_payload_raw = Cstruct.t

      let header_can_be_modified_inplace = false

      let icmpv4_header_to_src_addr header = header.src_addr

      let icmpv4_header_to_dst_addr header = header.dst_addr

      let icmpv4_header_to_icmpv4_type header = header.ty

      let make_icmpv4_header ~src_addr ~dst_addr ty =
        {src_addr; dst_addr; ty}

      let update_icmpv4_header_inplace ~src_addr:_ ~dst_addr:_ _ty _header = ()

      let update_icmpv4_header_inplace_byte_string ~src_addr:_ ~dst_addr:_ _ty
          _header =
        ()

      let icmpv4_payload_raw_to_byte_string c = Cstruct.to_string c

      let byte_string_to_icmpv4_payload_raw s = Cstruct.of_string s
    end

    module ICMPv6 = Firewall_tree.Mock_tree_base.ICMPv6

    module TCP = struct
      type tcp_port = int

      type tcp_header =
        { src_port : tcp_port
        ; dst_port : tcp_port
        ; ack : bool
        ; rst : bool
        ; syn : bool
        ; fin : bool }

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

      let update_tcp_header_inplace ~src_port:_ ~dst_port:_ ~ack:_ ~rst:_ ~syn:_
          ~fin:_ _header =
        ()

      let tcp_payload_raw_to_byte_string c = Cstruct.to_string c

      let byte_string_to_tcp_payload_raw s = Cstruct.of_string s
    end

    module UDP = struct
      type udp_port = int

      type udp_header = {src_port : udp_port; dst_port : udp_port}

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

  module FT = Firewall_tree.Make(Base)

  module Selectors = Firewall_tree.Selectors.Make(FT)

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
    TCP (TCP_pdu { header; payload = TCP_payload_raw data_raw })

  let data_to_udp_header data =
    let src_port = Udp_wire.get_udp_source_port data in
    let dst_port = Udp_wire.get_udp_dest_port data in
    FT.UDP.make_udp_header ~src_port ~dst_port

  let data_to_udp_pdu data =
    let open FT.PDU in
    let header = data_to_udp_header data in
    let data_offset = 8 in
    let data_raw = Cstruct.shift data data_offset in
    UDP (UDP_pdu { header; payload = UDP_payload_raw data_raw })

  let get_icmpv4_id_seq data : string * int =
    let id = Printf.sprintf "%02X" (Icmpv4_wire.get_icmpv4_id data) in
    let seq = Icmpv4_wire.get_icmpv4_seq data in
    (id, seq)


  let rlu_ipv4 = FT.RLU_IPv4.make ()
  let rlu_ipv6 = FT.RLU_IPv6.make ()

  (* define our policy through firewall tree *)
  let ftree =
    let open FT in
    Start { default = Drop;
            next = Select (Selectors.make_pdu_based_load_balancer_round_robin
                             [| End Drop
                              ; End Forward
                             |])
          }

  let start c m n e a i4 icmp4 tcp =
    (* make a wrapper to call FT.decide and react to outcome *)
    let react pdu =
      match FT.decide ftree ~src_netif:Net0 rlu_ipv4 rlu_ipv6 pdu with
      | (Drop, _) -> C.log c "Drop"
      | (Forward, pdu) -> (
          C.log c "Forward"
        )
      | (Echo_reply, _) -> (
          C.log c "Echo_reply" <&>
          match FT.PDU_to.icmpv4_pkt pdu with
          | None -> Lwt.return_unit
          | Some (ICMPv4_pkt { header; payload }) ->
            let src = FT.ICMPv4.icmpv4_header_to_src_addr header in
            let dst = FT.ICMPv4.icmpv4_header_to_dst_addr header in
            let ICMPv4_payload_raw data = payload in
            ICMP4.input icmp4 ~src ~dst data
        )
    in
    N.listen n ~header_size:Ethernet_wire.sizeof_ethernet
      (E.input
         ~arpv4:(A.input a)
         ~ipv4:(I4.input
                  ~tcp:(fun ~src:src_addr ~dst:dst_addr data ->
                      let open FT.PDU in
                      let header = FT.IPv4.make_ipv4_header ~src_addr ~dst_addr in
                      let tcp_pdu = data_to_tcp_pdu data in
                      let pdu = Layer3 (IPv4 (IPv4_pkt { header; payload = IPv4_payload_encap tcp_pdu })) in
                      react pdu
                    )
                  ~udp:(fun ~src:src_addr ~dst:dst_addr data ->
                      let open FT.PDU in
                      let header = FT.IPv4.make_ipv4_header ~src_addr ~dst_addr in
                      let udp_pdu = data_to_udp_pdu data in
                      let pdu = Layer3 (IPv4 (IPv4_pkt { header; payload = IPv4_payload_encap udp_pdu })) in
                      react pdu
                    )
                  ~default:(fun ~proto ~src:src_addr ~dst:dst_addr data ->
                      let open FT.PDU in
                      if proto = 1 then
                        let open FT.ICMPv4 in
                        match Icmpv4_wire.get_icmpv4_ty data |> Icmpv4_wire.int_to_ty with
                          | None -> Lwt.return_unit
                          | Some ty ->
                            let ty =
                              match ty with
                              | Echo_reply ->
                                let (id, seq) = get_icmpv4_id_seq data in ICMPv4_Echo_reply {id; seq}
                              | Destination_unreachable -> ICMPv4_Destination_unreachable
                              | Source_quench -> ICMPv4_Source_quench
                              | Redirect -> ICMPv4_Redirect
                              | Echo_request ->
                                let (id, seq) = get_icmpv4_id_seq data in ICMPv4_Echo_request {id; seq}
                              | Time_exceeded -> ICMPv4_Time_exceeded
                              | Parameter_problem -> ICMPv4_Parameter_problem
                              | Timestamp_request ->
                                let (id, seq) = get_icmpv4_id_seq data in ICMPv4_Timestamp_request {id; seq}
                              | Timestamp_reply ->
                                let (id, seq) = get_icmpv4_id_seq data in ICMPv4_Timestamp_reply {id; seq}
                              | Information_request ->
                                let (id, seq) = get_icmpv4_id_seq data in ICMPv4_Information_request {id; seq}
                              | Information_reply ->
                                let (id, seq) = get_icmpv4_id_seq data in ICMPv4_Information_reply {id; seq}
                            in
                            let header = FT.ICMPv4.make_icmpv4_header ~src_addr ~dst_addr ty in
                            let pdu = Layer3 (ICMPv4 (ICMPv4_pkt { header; payload = ICMPv4_payload_raw data })) in
                            react pdu
                      else
                        Lwt.return_unit
                    )
                  i4)
         ~ipv6:(fun _ -> Lwt.return_unit)
         e)
end
