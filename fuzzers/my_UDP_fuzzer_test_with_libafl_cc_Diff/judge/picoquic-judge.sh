#!/bin/bash
ps aux | grep picoquicdemo-network | grep -v grep | awk '{print $2}' | head -n 1
