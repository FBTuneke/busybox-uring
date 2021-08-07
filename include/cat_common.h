#pragma once

#include "../../linux/usr/include/linux/bpf.h"
#include "../../linux/usr/include/linux/io_uring.h"
#include <stdbool.h>

enum { BUFFER_SIZE = 4096 };

typedef unsigned long int longword;

#define DEFAULT_CQ_IDX 0
#define OPEN_CQ_IDX 1
#define READ_CQ_IDX 2
#define WRITE_CQ_IDX 3
#define SINK_CQ_IDX 4

#define CAT_COMPLETE 99909
#define READ_CQ_ERROR 99900
#define CONTEXT_ERROR 99901
#define READ_ERROR 99902
#define OPEN_CQ_ERROR 99903

#define CAT_PROG_IDX 0

#define AT_FDCWD -100

#define MAX_FDS 16

typedef struct _ebpf_context
{
      char buffer[BUFFER_SIZE];
      char *paths_userspace_ptr[MAX_FDS];
      char *buffer_userspace_ptr;
      unsigned int nr_of_files;
      unsigned int current_file_idx;
      int fd;
      unsigned long long write_offset;
      unsigned long long read_offset;
} ebpf_context_t;
