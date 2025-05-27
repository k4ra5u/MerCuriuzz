#!/bin/bash
ps aux | grep "main" | grep -v grep | awk '{print $2}' | head -n 1