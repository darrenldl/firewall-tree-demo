#!/bin/bash

opam uninstall firewall-tree && opam install firewall-tree

cd demos/internet-proxy/

make clean
mirage configure -t hvt --ipv4=192.168.0.100
make

./solo5-hvt --net=tap100 proxy.hvt
