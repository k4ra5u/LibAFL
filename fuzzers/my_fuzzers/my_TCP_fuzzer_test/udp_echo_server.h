#ifndef LIBAFL_SECOND_H
#define LIBAFL_SECOND_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>


#define PORT 12345
#define BUFFER_SIZE 1024
#define ACCEPT true
#define REJECT false


int udp_echo();

#endif  // LIBAFL_SECOND_H
