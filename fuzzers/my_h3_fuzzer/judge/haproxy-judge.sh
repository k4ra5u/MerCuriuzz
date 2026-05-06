#!/bin/bash
ps aux | grep haproxy/haproxy | grep -v grep | awk '{print $2}' | head -n 1

