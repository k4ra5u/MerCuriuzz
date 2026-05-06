nohup taskset -c 68,69 /home/john/quic-fuzz/newest/quic-go/example/main -bind 0.0.0.0:27443 -cert server.key >> quic-go.txt 2>&1 &
