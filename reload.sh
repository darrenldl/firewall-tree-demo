#!/bin/bash

if [[ $1 == "" ]]; then
  opam uninstall firewall-tree && opam install -w firewall-tree
fi

cd demos/internet-proxy/

mirage clean
mirage configure -t hvt --ipv4=192.168.0.100/24
make

./solo5-hvt --net=tap100 proxy.hvt
