open Lwt.Infix
open Mirage_types_lwt

module Main (C : CONSOLE) (MClock: MCLOCK) (N : NETWORK) (E : ETHERNET) (A : ARP) (I4 : IPV4) (ICMP4 : ICMPV4) (T : TCP) = struct
  module Base = struct
    let id x = x

    type decision = Drop | Forward | Echo_reply

    type netif = Net0

    let cur_time_ms () = Int64.div (MClock.elapsed_ns ()) 1000L

    module Ether = Firewall_tree.Mock_tree_base.Ether

    module IPv4 = struct
      type ipv4_addr = Ipaddr.V4.t

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

      let ipv4_payload_raw_to_byte_string c = Cstruct.to_string c
      let byte_string_to_ipv4_payload_raw s = Cstruct.of_string s
    end

    module IPv6 = Firewall_tree.Mock_tree_base.IPv6

    module ICMPv4 = struct
      open IPv4

      type icmpv4_type =
        | ICMPv4_Echo_reply
        | ICMPv4_Echo_request
        | ICMPv4_Timestamp_request
        | ICMPv4_Timestamp_reply

      type icmpv4_header =
        {src_addr : ipv4_addr; dst_addr : ipv4_addr; ty : icmpv4_type}

      type icmpv4_payload_raw = string

      let icmpv4_header_to_src_addr header = header.src_addr

      let icmpv4_header_to_dst_addr header = header.dst_addr

      let icmpv4_header_to_icmpv4_type header = header.ty

      let make_icmpv4_header ~src_addr ~dst_addr ty =
        {src_addr; dst_addr; ty}

      let icmpv4_payload_raw_to_byte_string = id

      let byte_string_to_icmpv4_payload_raw = id
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

      type tcp_payload_raw = string

      let compare_tcp_port = compare

      let tcp_header_to_src_port header = header.src_port

      let tcp_header_to_dst_port header = header.dst_port

      let tcp_header_to_ack_flag header = header.ack

      let tcp_header_to_rst_flag header = header.rst

      let tcp_header_to_syn_flag header = header.syn

      let tcp_header_to_fin_flag header = header.fin

      let make_tcp_header ~src_port ~dst_port ~ack ~rst ~syn ~fin =
        {src_port; dst_port; ack; rst; syn; fin}

      let tcp_payload_raw_to_byte_string = id

      let byte_string_to_tcp_payload_raw = id
    end

    module UDP = struct
      type udp_port = int

      type udp_header = {src_port : udp_port; dst_port : udp_port}

      type udp_payload_raw = string

      let compare_udp_port = compare

      let udp_header_to_src_port header = header.src_port

      let udp_header_to_dst_port header = header.dst_port

      let make_udp_header ~src_port ~dst_port = {src_port; dst_port}

      let udp_payload_raw_to_byte_string = id

      let byte_string_to_udp_payload_raw = id
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

  let rlu_ipv4 = FT.RLU_IPv4.make ()
  let rlu_ipv6 = FT.RLU_IPv6.make ()

  let ftree =
    let open FT in
    Start { default = Drop;
            next = Select (Selectors.make_pdu_based_load_balancer_round_robin
                             [| End Drop
                              ; End Forward
                             |])
          }

  let start c m n e a i4 icmp4 tcp =
    N.listen n ~header_size:Ethernet_wire.sizeof_ethernet
      (E.input
         ~arpv4:(A.input a)
         ~ipv4:(I4.input
                  ~tcp:(fun ~src:src_addr ~dst:dst_addr data ->
                      let ipv4_header = FT.IPv4.make_ipv4_header ~src_addr ~dst_addr in
                      let tcp_header = data_to_tcp_header data in
                      Lwt.return_unit
                    )
                  ~udp:(fun ~src:src_addr ~dst:dst_addr data ->
                      let ipv4_header = FT.IPv4.make_ipv4_header ~src_addr ~dst_addr in
                      Lwt.return_unit
                    )
                  ~default:(fun ~proto ~src:src_addr ~dst:dst_addr data ->
                      let open FT.PDU in
                      let ipv4_header = FT.IPv4.make_ipv4_header ~src_addr ~dst_addr in
                      let pdu = Layer3 (IPv4 (IPv4_pkt { header = ipv4_header; payload = IPv4_payload_raw data })) in
                      match FT.decide ftree ~src_netif:Net0 rlu_ipv4 rlu_ipv6 pdu with
                      | (Drop, _) -> C.log c "Drop"
                      | (Forward, p) -> (
                          C.log c "Forward" <&>
                          C.log c (FT.To_debug_string.pdu_to_debug_string p) <&>
                          ICMP4.input icmp4
                            ~src:src_addr ~dst:dst_addr data
                        )
                      | (Echo_reply, _) -> C.log c "Echo_reply"
                    )
                  i4)
         ~ipv6:(fun _ -> Lwt.return_unit)
         e) >>= (fun _ -> Lwt.return_unit)
end
