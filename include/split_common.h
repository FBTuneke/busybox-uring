#pragma once

#include "../include/libbb.h"
#include "../../linux/usr/include/linux/bpf.h"
#include "../../linux/usr/include/linux/io_uring.h"
// #define read_buffer bb_common_bufsiz1
// enum { READ_BUFFER_SIZE = COMMON_BUFSIZE - 1 };
enum { READ_BUFFER_SIZE = 1024 };
// enum { READ_BUFFER_SIZE = 2048 };
// enum { READ_BUFFER_SIZE = 3072 };
// enum { READ_BUFFER_SIZE = 4096 };
// enum { READ_BUFFER_SIZE = 5120 };
// enum { READ_BUFFER_SIZE = 6144 };
// enum { READ_BUFFER_SIZE = 10240 };
// enum { READ_BUFFER_SIZE = 20480 };
// enum { READ_BUFFER_SIZE = 40960 };
// enum { READ_BUFFER_SIZE = 51200 };
// enum { READ_BUFFER_SIZE = 61440 };
// enum { READ_BUFFER_SIZE = 102400 };
// enum { READ_BUFFER_SIZE = 614400 };
//  enum { READ_BUFFER_SIZE = 1228800 };

#define DEFAULT_CQ_IDX 0
#define READ_CQ_IDX 1
#define OPEN_CQ_IDX 2
#define SINK_CQ_IDX 3

#define SPLIT_PROG 0

#define SPLIT_COMPLETE 99997
#define SUFFIX_EXHAUSTED 99996

#define AT_FDCWD -100

typedef struct _ebpf_context
{
      char read_buffer[READ_BUFFER_SIZE];
      int cnt;
      char *read_buffer_userspace_base_ptr;
      char pfx_buffer[NAME_MAX]; //NAME_MAX ist von busybox = 255.
      char *pfx_buffer_userspace_base_ptr;
      uint16_t suffix_len;
      uint16_t pfx_len;

} ebpf_context_t;
