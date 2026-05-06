nohup taskset -c 70,71 /home/john/quic-fuzz/newest/h3-check/haproxy/haproxy -d -V -f quic.cfg >> haproxy.txt 2>&1 & 
