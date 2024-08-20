#!/bin/bash
ps aux | grep /home/john/Desktop/cjj_related/testing_new/h2o/Debug/bin/h2o | grep -v grep | awk '{print $2}'
