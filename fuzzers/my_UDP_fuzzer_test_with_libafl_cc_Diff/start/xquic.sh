#!/bin/bash
nohup taskset -c 60,61 /home/john/quic-fuzz/newest/xquic/build-cov-nohost/tests/test_server-network -a 127.0.0.1 -p 28443 >> xquic.txt 2>&1 & 
