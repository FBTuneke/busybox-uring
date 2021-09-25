#pragma once

#include "../../linux/usr/include/linux/bpf.h"
#include "../../linux/usr/include/linux/io_uring.h"
#include <stdbool.h>
#include "../include/conditional_compilation.h"
// #define read_buffer bb_common_bufsiz1
// enum { READ_BUFFER_SIZE = COMMON_BUFSIZE - 1 };
// enum { READ_BUFFER_SIZE = 1024 };
// enum { READ_BUFFER_SIZE = 2048 };
// enum { READ_BUFFER_SIZE = 3072 };
enum { READ_BUFFER_SIZE = 4096 };
// enum { READ_BUFFER_SIZE = 5120 };
// enum { READ_BUFFER_SIZE = 6144 };
// enum { READ_BUFFER_SIZE = 10240 };
// enum { READ_BUFFER_SIZE = 16384 };
// enum { READ_BUFFER_SIZE = 20480 };
// enum { READ_BUFFER_SIZE = 40960 };
// enum { READ_BUFFER_SIZE = 51200 };
// enum { READ_BUFFER_SIZE = 61440 };
// enum { READ_BUFFER_SIZE = 102400 };
// enum { READ_BUFFER_SIZE = 614400 };
//  enum { READ_BUFFER_SIZE = 1228800 };

typedef unsigned long int longword;

#define DEFAULT_CQ_IDX 0
#define READ_CQ_IDX 1
#define OPEN_CQ_IDX 2
#define SINK_CQ_IDX 3

#define OPEN_PROG_IDX 0
#define SPLIT_PROG_IDX 1

#define SPLIT_COMPLETE 99997
#define SUFFIX_EXHAUSTED 99996

#define AT_FDCWD -100

#define STDIN_FILENO_FIX 0

#define FIXED_FDS_SIZE 2

typedef struct _ebpf_context
{
      char read_buffer[READ_BUFFER_SIZE];
      off_t cnt; //number of lines to split by
      char *read_buffer_userspace_base_ptr;
      char pfx_buffer[NAME_MAX + 1]; //NAME_MAX ist von busybox = 255.
      char *pfx_buffer_userspace_base_ptr;
      uint16_t suffix_len;
      uint16_t pfx_len;
      longword read_buffer_base_int; //ARGH! Verifier erlaubt keine modulo-Operation auf Addressen, also erst in Variable speichern. In normaler Stack-Variable meckert er auch. Aus der Map geht's klar.
      unsigned int fixed_fd;
} ebpf_context_t;
