nohup taskset -c 42,43 /home/john/quic-fuzz/newest/picoquic/build-cov/picoquicdemo -c /home/john/quic-fuzz/certs/server.crt -k /home/john/quic-fuzz/certs/server.key -p 48440 >> picoquic.txt 2>&1 & 
