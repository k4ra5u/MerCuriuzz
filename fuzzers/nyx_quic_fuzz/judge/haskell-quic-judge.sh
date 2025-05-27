#!/bin/bash
ps aux | grep "quic-server" | grep -v grep | awk '{print $2}' | head -n 1