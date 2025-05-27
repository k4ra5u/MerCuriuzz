nohup taskset -c 52,53 /home/john/quic-fuzz/newest/quinn/target/debug/perf_server --listen 0.0.0.0:58440 >> quinn.txt 2>&1 &
