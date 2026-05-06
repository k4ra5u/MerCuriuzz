#!/bin/bash
ps -ef | grep h2o-network-quic-fuzz | grep -v grep | awk '{print $2}' | head -n 1