#!/bin/bash
ps aux | grep "worker process" | grep -v grep | awk '{print $2}' | head -n 1
