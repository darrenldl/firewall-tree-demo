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
  (* We define our environment implementation (or tree base) for the firewall tree *)
  module Base = struct
    let id x = x

    (* Decision can be arbitrarily defined, and is part of the outcome

       We only care about three decisions for now, we can always add more later
    *)
    type decision = Drop | Forward | Echo_reply | Test

    (* This is just for the firewall-tree library to distinguish between
       interfaces

       We only have one interface, so we use a single variant here
    *)
    type netif = Net0

    (* firewall-tree needs access to current time for timed out entries
       cleanup in Lookup_table, which is used for connection tracking,
       translation etc
    *)
    let cur_time_ms () = Int64.div (MClock.elapsed_ns ()) 1_000_000L

    (* we don't care about ethernet frames, use dummy implementation *)
    module Ether = Firewall_tree.Mock_tree_base.Ether

    module IPv4 = struct
      type ipv4_addr = Ipaddr.V4.t

      type ipv4_header = {mutable src_addr: ipv4_addr; mutable dst_addr: ipv4_addr}

      type ipv4_payload_raw = Cstruct.t

      let compare_ipv4_addr = Ipaddr.V4.compare

      let ipv4_addr_to_byte_string = Ipaddr.V4.to_bytes

      let byte_string_to_ipv4_addr = Ipaddr.V4.of_bytes_exn

      let ipv4_header_to_src_addr r = r.src_addr

      let ipv4_header_to_dst_addr r = r.dst_addr

      (* To reduce complexity of PDU manipulation, firewall-tree does not
         require a full-blown make header function that produces a fully valid header

         Instead, we are only required to provide a update header function which provides
         access to several fields rather than all, and a dummy header function for testing
         purposes only

         Header types can be mutable or immutable (update header functions return a copy of header anyway),
         we're picking mutable here as it allows easier modification
      *)
      let make_dummy_ipv4_header () =
        {src_addr = Ipaddr.V4.make 192 168 0 1;
         dst_addr = Ipaddr.V4.make 192 168 0 2}

      let update_ipv4_header_ ~src_addr ~dst_addr header =
        (match src_addr with
         | None -> ()
         | Some x -> header.src_addr <- x
        );
        (match dst_addr with
         | None -> ()
         | Some x -> header.dst_addr <- x
        );
        header

      let update_ipv4_header_byte_string_ ~src_addr ~dst_addr
          header =
        (match src_addr with
         | None -> ()
         | Some x -> header.src_addr <- Ipaddr.V4.of_bytes_exn x
        );
        (match dst_addr with
         | None -> ()
         | Some x -> header.dst_addr <- Ipaddr.V4.of_bytes_exn x
        );
        header

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
        {mutable ty: icmpv4_type}

      type icmpv4_payload_raw = Cstruct.t

      let header_can_be_modified_inplace = false

      let icmpv4_header_to_icmpv4_type header = header.ty

      let make_dummy_icmpv4_header ty =
        {ty = ICMPv4_Echo_reply {id = "\x01\x01"; seq = 0}}

      let update_icmpv4_header_ ty header =
        (match ty with None -> () | Some x -> header.ty <- x);
        header

      let icmpv4_payload_raw_to_byte_string c = Cstruct.to_string c

      let byte_string_to_icmpv4_payload_raw s = Cstruct.of_string s
    end

    module ICMPv6 = Firewall_tree.Mock_tree_base.ICMPv6

    module TCP = struct
      type tcp_port = Cstruct.uint16

      type tcp_header = Tcp.Tcp_packet.t

      type tcp_payload_raw = Cstruct.t

      let header_can_be_modified_inplace = false

      let compare_tcp_port = compare

      open Tcp.Tcp_packet

      let tcp_header_to_src_port h = h.src_port

      let tcp_header_to_dst_port h = h.dst_port

      let tcp_header_to_ack_flag h = h.ack

      let tcp_header_to_rst_flag h = h.rst

      let tcp_header_to_syn_flag h = h.syn

      let tcp_header_to_fin_flag h = h.fin

      let make_dummy_tcp_header () =
        {
          urg = false;
          ack = false;
          psh = false;
          rst = false;
          syn = true;
          fin = false;
          window = 0;
          options = [];
          sequence = Tcp.Sequence.of_int 0;
          ack_number = Tcp.Sequence.of_int 0;
          src_port = 1000;
          dst_port = 1001; }

      let update_tcp_header_ ~src_port ~dst_port ~ack ~rst ~syn ~fin header =
        let open Tcp.Tcp_wire in
        let src_port =
          match src_port with
          | None -> header.src_port
          | Some x -> x
        in
        let dst_port =
          match dst_port with
          | None -> header.dst_port
          | Some x -> x
        in
        let fin = match fin with
          | None -> header.fin
          | Some x -> x
        in
        let syn = match syn with
          | None -> header.syn
          | Some x -> x
        in
        let rst = match rst with
          | None -> header.rst
          | Some x -> x
        in
        let psh = header.psh in
        let ack = match ack with
          | None -> header.ack
          | Some x -> x
        in
        let urg = header.urg in
        let window = header.window in
        let options = header.options in
        let sequence = header.sequence in
        let ack_number = header.ack_number in

        { urg
        ; ack
        ; psh
        ; rst
        ; syn
        ; fin
        ; window
        ; options
        ; sequence
        ; ack_number
        ; src_port
        ; dst_port }

      let tcp_payload_raw_to_byte_string c = Cstruct.to_string c

      let byte_string_to_tcp_payload_raw s = Cstruct.of_string s
    end

    module UDP = Firewall_tree.Mock_tree_base.UDP
  end

  (* We feed the environment implementation to the functor to get our tree *)
  module FT = Firewall_tree.Make (Base)

  (* We also want to use selectors, modifiers and scanners provided by firewall-tree *)
  module Selectors = Firewall_tree.Selectors.Make (FT)
  module Modifiers = Firewall_tree.Modifiers.Make (FT)
  module Scanners = Firewall_tree.Scanners.Make (FT)

  (* We define some helpers to help wrapping things into processable types
     for the tree
  *)
  module Helpers = struct
    let data_to_tcp_pdu data =
      let open FT.PDU in
      match Tcp.Tcp_packet.Unmarshal.of_cstruct data with
      | Error _ -> None
      | Ok (header, payload) ->
        Some (TCP (TCP_pdu {header; payload = TCP_payload_raw payload}))

    let get_icmpv4_ty data : FT.ICMPv4.icmpv4_type option =
      let open FT.ICMPv4 in
      let get_icmpv4_id_seq data : string * int =
        let id_int = Icmpv4_wire.get_icmpv4_id data in
        let id_raw = Marshal.to_string id_int [] in
        let len = String.length id_raw in
        let id_str = String.sub id_raw (len - 2) 2 in
        let seq = Icmpv4_wire.get_icmpv4_seq data in
        (id_str, seq)
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

  (* We don't actually need Routing Logic Unit (RLU) here,
     and they are not fully functional yet

     But they are mandatory for the decide function as
     RLU is necessary to determine egress network interface
     and next-hop address etc, which may be used in the policy
  *)
  let rlu_ipv4 = FT.RLU_IPv4.make ()
  let rlu_ipv6 = FT.RLU_IPv6.make ()


  let start c m n e a i4 icmp4 tcp =
  (* Finally we define our policy through firewall tree

     See the diagram for a clearer representation
  *)
  let ftree =
    let open FT in
    let open Pred in
    let open Selectors in
    let open Scanners in
    let open Modifiers in
    let tracker = Conn_track.make ~max_conn:1000 ~init_size:10 ~timeout_ms:30_000L in
    let addr = List.hd (I4.get_ip i4) in
    let side_A_addr = addr in
    let side_B_addr = addr in
    let side_B_port_start = 1000 in
    let side_B_port_end_exc = 15_000 in
    let { side_A_to_B_branch; side_B_to_A_branch } =
      let dst_addrs =
        [| Ipaddr.V4.make 192 168 0 254
             (* [| Ipaddr.V4.make 216 58 196 132 *)
        |]
      in
      translate_ipv4_side_A_to_random_dst_side_B ~conn_tracker:tracker ~side_A_addr ~side_B_addr
        ~side_B_port_start ~side_B_port_end_exc ~dst_addrs ~max_conn:1000
        (End Forward)
    in
    Start
      { default = Drop
      ; next =
          select_first_match
            (* This selects the first branch with a satisfied predicate

               We use the same connection tracker for all predicates so they share
               the same information, which is what we want

               Connection trackers are bidirectional, and will lookup which one is the
               initiator and which one is the responder if needed for a protocol (e.g. TCP),
               so we don't have to worry too much about placement

               `Invalid` connection is implicitly dropped here

               Selectors can drop a pdu, which results in default decision,
               by picking a negative or out of bound branch index
            *)
            [| Conn_state_eq { tracker; target_state = Conn_track.New }, (* We consider all new traffic to be from side A to B during translation *)
               select_first_match [| Contains_ICMPv4,
                                     filter ICMPv4_ty_eq_Echo_request (* We reply every other ECHO request we receive *)
                                       (load_balance_pdu_based_round_robin [| End Drop
                                                                            ; (* Connection trackers are run in immutable mode in predicate
                                                                                      evaluation, so we need to pass the PDU through the tracker
                                                                                      again to actually update the connection state
                                                                              *)
                                                                              pass_pdu_through_conn_tracker tracker
                                                                                (End Echo_reply)
                                                                           |])
                                   ; Contains_TCP,
                                     (* We block HTTP traffic naively, and translate supposedly HTTPS traffic *)
                                     select_first_match [| TCP_dst_port_eq 80, End Drop
                                                         ; True, side_A_to_B_branch
                                                        |]
                                  |]
             ; Conn_state_eq { tracker; target_state = Conn_track.Established }, (* We consider all established traffic to be from side B to A during translation *)
               side_B_to_A_branch
             ; True, End Test
            |]
      }
      in
    (* Make a wrapper to call FT.decide and react to outcome *)
    let react pdu =
      (* Print out PDU for debugging/demo purpose *)
      C.log c (
        "Received pdu\n"
        ^
        (FT.To_debug_string.pdu pdu) (* To_debug_string.pdu is a pretty printer for PDUs provided by firewall-tree *)
      ) >>=
      (fun _ ->
         match FT.decide ftree ~src_netif:Net0 rlu_ipv4 rlu_ipv6 pdu with
         | Drop, _ ->
           C.log c "Decision : Drop\n"
         | Forward, pdu -> (
             C.log c "Decision : Forward\n"
             <&>
             match FT.PDU_to.ipv4_header pdu, FT.PDU_to.tcp_pdu pdu with
             | Some ipv4_header, Some (TCP_pdu {header = tcp_header; payload = TCP_payload_raw payload }) -> (
                 let src_addr = FT.IPv4.ipv4_header_to_src_addr ipv4_header in
                 let dst_addr = FT.IPv4.ipv4_header_to_dst_addr ipv4_header in
                 let tcp_len = Tcp.Tcp_wire.sizeof_tcp + Cstruct.len payload in
                 C.log c (Printf.sprintf "sizeof_tcp : %d, payload len : %d" Tcp.Tcp_wire.sizeof_tcp (Cstruct.len payload)) >>= (fun _ ->
                     let pseudoheader = I4.pseudoheader i4 ~src:src_addr dst_addr `TCP (Ipv4_wire.sizeof_ipv4 + tcp_len) in
                     let headerf buffer =
                       match Tcp.Tcp_packet.Marshal.into_cstruct ~pseudoheader ~payload tcp_header buffer with
                       | Error e -> failwith e
                       | Ok len -> len
                     in
                     I4.write i4 ~src:src_addr dst_addr `TCP ~size:(Ipv4_wire.sizeof_ipv4 + tcp_len) headerf [payload] >>=
                     (fun _ -> Lwt.return_unit)
                   )
               )
             | _, _ -> Lwt.return_unit
           )
         | Echo_reply, _ -> (
             C.log c "Decision : Echo_reply\n"
             <&>
             match FT.PDU_to.ipv4_header pdu, FT.PDU_to.icmpv4_pkt pdu with
             | Some ipv4_header, Some (ICMPv4_pkt {header; payload}) ->
               let src = FT.IPv4.ipv4_header_to_src_addr ipv4_header in
               let dst = FT.IPv4.ipv4_header_to_dst_addr ipv4_header in
               let (ICMPv4_payload_raw data) = payload in
               ICMP4.input icmp4 ~src ~dst data
             | _ -> Lwt.return_unit
           )
         | Test, _ -> C.log c "Decision : Test\n"
      )
    in
    N.listen n ~header_size:Ethernet_wire.sizeof_ethernet
      (E.input ~arpv4:(A.input a)
         ~ipv4:
           (I4.input
              ~tcp:(fun ~src:src_addr ~dst:dst_addr data ->
                let open FT.PDU in
                let open Base.IPv4 in
                let header = {src_addr; dst_addr} in
                match Helpers.data_to_tcp_pdu data with
                | None -> Lwt.return_unit
                | Some tcp_pdu ->
                  let pdu =
                    Layer3
                      (IPv4
                         (IPv4_pkt {header; payload= IPv4_payload_encap tcp_pdu}))
                  in
                  react pdu )
              ~udp:(fun ~src:src_addr ~dst:dst_addr data -> Lwt.return_unit)
              ~default:(fun ~proto ~src:src_addr ~dst:dst_addr data ->
                let open FT.PDU in
                let open Base.IPv4 in
                let open Base.ICMPv4 in
                if proto = 1 then
                  (* only care about ICMP *)
                  match Helpers.get_icmpv4_ty data with
                  | None ->
                      Lwt.return_unit
                  | Some ty ->
                      let ipv4_header =
                        {src_addr; dst_addr}
                      in
                      let icmpv4_pkt =
                        let header =
                          { ty }
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
