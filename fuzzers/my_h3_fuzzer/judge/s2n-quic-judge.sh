#!/bin/bash
ps aux | grep quic_echo_server | grep -v grep | awk '{print $2}' | head -n 1