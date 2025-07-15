#!/bin/bash
ps aux | grep examples/http3_server.py | grep -v grep | awk '{print $2}' | head -n 1