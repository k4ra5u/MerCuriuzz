nohup taskset -c 56,57  /home/john/quic-fuzz/newest/ngtcp2/examples/bsslserver 0.0.0.0 30443 /home/john/quic-fuzz/certs/server.key /home/john/quic-fuzz/certs/server.crt >> ngtcp2.txt 2>&1 &
