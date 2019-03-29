open Mirage

let packages = [
  package "ethernet";
  package "firewall-tree";
]

let main =
  foreign
    ~packages
    "Unikernel.Main" (console @-> network @-> job)

let () =
  register "ft-demo0" [ main $ default_console $ default_network ]
