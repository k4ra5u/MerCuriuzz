#!/bin/bash
ps aux | grep quiche-server | grep -v grep | awk '{print $2}' | head -n 1