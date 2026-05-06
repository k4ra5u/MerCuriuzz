#!/bin/bash
ps aux | grep bsslserver | grep -v grep | awk '{print $2}' | head -n 1