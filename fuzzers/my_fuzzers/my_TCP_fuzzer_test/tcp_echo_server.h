#ifndef LIBAFL_FIRST_H
#define LIBAFL_FIRST_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 12346
#define BUFFER_SIZE 1024

#define ACCEPT true
#define REJECT false

int tcp_echo();

#endif  // LIBAFL_FIRST_H