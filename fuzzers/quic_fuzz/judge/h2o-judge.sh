#!/bin/bash
ps -ef | grep quic-fuzz/newest/h2o/release/bin | grep -v grep | awk '{print $2}' | head -n 1