#!/bin/bash
nohup taskset -c 60,61 /home/john/quic-fuzz/newest/lsquic/build/bin/http_server-network-quic-fuzz -s 0.0.0.0:25443 -L ERROR -r ./ -c 127.0.0.1,/home/john/quic-fuzz/certs/server.crt,/home/john/quic-fuzz/certs/server.key >> lsquic.txt 2>&1 & 
