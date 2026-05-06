#!/bin/bash
ps aux | grep neqo-server | grep -v grep | awk '{print $2}' | head -n 1
