#!/bin/bash
nohup taskset -c 54,55 /home/john/quic-fuzz/newest/h3-check/xquic/build/tests/test_server-network -a 127.0.0.1 -p 28443 >> xquic.txt 2>&1 & 
