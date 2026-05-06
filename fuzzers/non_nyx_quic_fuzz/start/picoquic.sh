#!/bin/bash
nohup taskset -c 62,63 /home/john/quic-fuzz/newest/picoquic/build-cov/picoquicdemo-network -c /home/john/quic-fuzz/certs/server.crt -k /home/john/quic-fuzz/certs/server.key -p 28440 >> picoquic.txt 2>&1 & 
