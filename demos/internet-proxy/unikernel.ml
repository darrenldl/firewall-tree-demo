open Lwt.Infix
open Mirage_types_lwt

module Main (C : CONSOLE) (MClock: MCLOCK) (N : NETWORK) (E : ETHERNET) (A : ARP) (I4 : IPV4) (T : TCP) = struct
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

      type ipv4_payload_raw = string

      let compare_ipv4_addr = Ipaddr.V4.compare

      let ipv4_addr_to_bytes = Ipaddr.V4.to_bytes

      let bytes_to_ipv4_addr = Ipaddr.V4.of_bytes_exn

      let ipv4_header_to_src_addr r = r.src_addr
      let ipv4_header_to_dst_addr r = r.dst_addr

      let make_ipv4_header ~src_addr ~dst_addr = { src_addr; dst_addr }

      let ipv4_payload_raw_to_bytes = id
      let bytes_to_ipv4_payload_raw = id
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

      let icmpv4_payload_raw_to_bytes = id

      let bytes_to_icmpv4_payload_raw = id
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

      let tcp_payload_raw_to_bytes = id

      let bytes_to_tcp_payload_raw = id
    end

    module UDP = struct
      type udp_port = int

      type udp_header = {src_port : udp_port; dst_port : udp_port}

      type udp_payload_raw = string

      let compare_udp_port = compare

      let udp_header_to_src_port header = header.src_port

      let udp_header_to_dst_port header = header.dst_port

      let make_udp_header ~src_port ~dst_port = {src_port; dst_port}

      let udp_payload_raw_to_bytes = id

      let bytes_to_udp_payload_raw = id
    end
  end

  module FT = Firewall_tree.Make(Base)

  let start c m n e a i4 tcp =
    N.listen n ~header_size:Ethernet_wire.sizeof_ethernet
      (E.input
         ~arpv4:(A.input a)
         ~ipv4:(I4.input
                  ~tcp:(fun ~src:src_addr ~dst:dst_addr data ->
                      let src_port = Tcp.Tcp_wire.get_tcp_src_port data in
                      Lwt.return_unit
                    )
                  ~udp:(fun ~src:src_addr ~dst:dst_addr data -> Lwt.return_unit)
                  ~default:(fun ~proto ~src:_ ~dst:_ _data -> C.log c "ping on side A")
                  i4)
         ~ipv6:(fun _ -> Lwt.return_unit)
         e) >>= (fun _ -> Lwt.return_unit)
end
