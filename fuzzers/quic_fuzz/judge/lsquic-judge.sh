#!/bin/bash
ps aux | grep lsquic/build/bin/http_server | grep -v grep | awk '{print $2}' | head -n 1
#ps aux | grep lsquic/build/bin/http_server 
#ps aux | grep http_server | grep -v grep | awk '{print $2}'
