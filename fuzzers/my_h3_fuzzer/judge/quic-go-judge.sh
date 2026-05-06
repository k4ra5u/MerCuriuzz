#!/bin/bash
ps aux | grep "quic-go/example/main" | grep -v grep | awk '{print $2}' | head -n 1