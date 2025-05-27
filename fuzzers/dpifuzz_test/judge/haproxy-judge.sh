#!/bin/bash
ps aux | grep haproxy | grep -v grep | awk '{print $2}' | head -n 1

