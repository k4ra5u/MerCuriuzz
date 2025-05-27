ps aux | grep picoquicdemo | grep -v grep | awk '{print $2}' | head -n 1
