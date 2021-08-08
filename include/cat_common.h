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
#define CLOSE_CQ_IDX 4
#define SINK_CQ_IDX 5

#define READ_CQ_ERROR 99900
#define CONTEXT_ERROR 99901
#define READ_ERROR 99902
#define OPEN_CQ_ERROR 99903
#define WRITE_ERROR 99904
#define OPEN_ERROR 99905
#define CLOSE_ERROR 99906
#define CLOSE_LAST_FILE_ERROR 99907
#define CLOSE_LAST_FILE_CQ_ERROR 99908
#define CAT_COMPLETE 99909

#define CAT_PROG_IDX 0
#define END_PROG_IDX 1

#define AT_FDCWD -100

#define MAX_FDS 32

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
      unsigned long nr_of_bytes_to_write;
} ebpf_context_t;
