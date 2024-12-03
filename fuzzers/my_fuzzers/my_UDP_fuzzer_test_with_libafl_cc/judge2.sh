#!/bin/bash
ps aux | grep /home/john/Desktop/cjj_related/testing_new/lsquic/build/bin/http_server | grep -v grep | awk '{print $2}' | head -n 1
#ps aux | grep http_server | grep -v grep | awk '{print $2}'
