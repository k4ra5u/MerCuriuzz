nohup taskset -c 52,53  /home/john/quic-fuzz/newest/ngtcp2/examples/bsslserver 0.0.0.0 58440 /home/john/quic-fuzz/certs/server.key /home/john/quic-fuzz/certs/server.crt >> ngtcp2.txt 2>&1 &
