#!/bin/bash
#nohup /home/john/Desktop/cjj_related/testing_new/fuzzing-test/LibAFL/fuzzers/my_fuzzers/my_UDP_fuzzer_test_with_libafl_cc/udp_echo_server &
nohup taskset -c 52,53 /home/john/Desktop/cjj_related/testing_new/lsquic/build/bin/http_server -s 0.0.0.0:58440 -L ERROR -r ./ -c 127.0.0.1,/home/john/Desktop/cjj_related/server.crt,/home/john/Desktop/cjj_related/server.key 2>&1 & 
