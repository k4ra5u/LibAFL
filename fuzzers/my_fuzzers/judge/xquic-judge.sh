#!/bin/bash
ps aux | grep test_server | grep -v grep | awk '{print $2}' | head -n 1