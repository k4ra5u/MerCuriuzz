nohup taskset -c 50,51 /home/john/quic-fuzz/newest/quinn/target/debug/perf_server --listen 0.0.0.0:31440 ./ >> quinn.txt 2>&1 &
