#!/bin/bash
#nohup /home/john/Desktop/cjj_related/testing_new/fuzzing-test/LibAFL/fuzzers/my_fuzzers/my_UDP_fuzzer_test_with_libafl_cc/udp_echo_server &
nohup taskset -c 20,21 /home/john/Desktop/cjj_related/testing_new/h2o/bin/bin/h2o 2>&1 & 
