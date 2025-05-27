#!/bin/bash
ps aux | grep quicsample | grep -v grep | awk '{print $2}' | head -n 1