#!/bin/bash
ps aux | grep test_server-network | grep -v grep | awk '{print $2}' | head -n 1