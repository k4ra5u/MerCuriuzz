nohup taskset -c 52,53 /home/john/quic-fuzz/newest/picoquic/build-cov/picoquicdemo -c /home/john/quic-fuzz/certs/server.crt -k /home/john/quic-fuzz/certs/server.key -p 58440 >> picoquic.txt 2>&1 & 
