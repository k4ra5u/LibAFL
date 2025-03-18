#!/bin/bash
#nohup /home/john/Desktop/cjj_related/testing_new/fuzzing-test/LibAFL/fuzzers/my_fuzzers/my_UDP_fuzzer_test_with_libafl_cc/udp_echo_server &
nohup taskset -c 50,51 /home/john/quic-fuzz/newest/lsquic/build/bin/http_server -s 0.0.0.0:58443 -L ERROR -r ./ -c 127.0.0.1,/home/john/quic-fuzz/certs/server.crt,/home/john/quic-fuzz/certs/server.key >> lsquic.txt 2>&1 & 
