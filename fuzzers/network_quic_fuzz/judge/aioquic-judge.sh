#!/bin/bash
ps aux | grep http3 | grep -v grep | awk '{print $2}' | head -n 1