#!/bin/bash
ps -ef | grep "bin/h2o" | grep -v grep | awk '{print $2}' | head -n 1