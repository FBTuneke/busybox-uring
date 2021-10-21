// #define _GNU_SOURCE

#include <inttypes.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "../include/cat_common.h"
#include "../../linux/tools/lib/bpf/bpf_helpers.h"
#include <sys/socket.h>
#include <unistd.h>
// #include <bpf/bpf_helper_defs.h>

// #define MAX_LOOP 1
#define STDOUT_FILENO_FIX MAX_FDS

struct bpf_map_def SEC("maps") context_map =
{
        .type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof(uint32_t),
        .value_size = sizeof(ebpf_context_t),
        .max_entries = 1,
        .map_flags = BPF_F_MMAPABLE,
};

// static long (*bpf_io_uring_submit)(void *bpf_ctx, struct io_uring_sqe *sqe, uint32_t sqe_len) = (void *) 170;
// static long (*bpf_io_uring_emit_cqe)(void *bpf_ctx, uint32_t cq_idx, __u64 user_data, int res, uint32_t flags) = (void *) 171;
// static long (*bpf_io_uring_reap_cqe)(void *bpf_ctx, uint32_t cq_idx, struct io_uring_cqe *cqe_out, uint32_t cqe_len) = (void *) 172;
// static long (*bpf_custom_copy_to_user)(void *user_ptr, const void *src, __u32 size) = (void *) 167; //overwrite normal bpf_copy_to_user

static inline void io_uring_prep_rw(int op, struct io_uring_sqe *sqe, int fd,const void *addr, unsigned len, __u64 offset)
{
	// sqe->opcode = op;
	// sqe->flags = 0;
	// sqe->ioprio = 0;
	// sqe->fd = fd;
	// sqe->off = offset;
	// sqe->addr = (unsigned long) addr;
	// sqe->len = len;
	// sqe->rw_flags = 0;
	// sqe->user_data = 0;
	// sqe->__pad2[0] = sqe->__pad2[1] = sqe->__pad2[2] = 0;

      sqe->opcode = (__u8) op;
	sqe->flags = 0;
	sqe->ioprio = 0;
	sqe->fd = fd;
	sqe->off = offset;
	sqe->addr = (unsigned long) addr;
	sqe->len = len;
	sqe->rw_flags = 0;
	sqe->user_data = 0;
	sqe->buf_index = 0;
	sqe->personality = 0;
	sqe->file_index = 0;
	sqe->__pad1 = 0;
	sqe->__pad2 = 0;
	sqe->__pad3 = 0;
}

static inline void io_uring_prep_openat(struct io_uring_sqe *sqe, int dfd, const char *path, int flags, mode_t mode)
{
	io_uring_prep_rw(IORING_OP_OPENAT, sqe, dfd, path, mode, 0);
	sqe->open_flags = flags;
}

static inline void io_uring_prep_bpf(struct io_uring_sqe *sqe, __u64 off,  __u64 user_data)
{
	io_uring_prep_rw(IORING_OP_BPF, sqe, 0, NULL, 0, off);   
	sqe->user_data = user_data;
}

static inline void io_uring_prep_close(struct io_uring_sqe *sqe, int fd)
{
      io_uring_prep_rw(IORING_OP_CLOSE, sqe, fd, NULL, 0, 0);
}

// int unsigned cnt = 0;
// int unsigned nr_of_write_repeats = 0;
SEC("iouring") 
int open_callback(struct io_uring_bpf_ctx *ctx)
{
      struct io_uring_sqe sqe;
	struct io_uring_cqe cqe;
      uint32_t key = 0;
      int ret;
      ebpf_context_t *context;

      context = (ebpf_context_t *) bpf_map_lookup_elem(&context_map, &key); 
      if(!context)
      {
            bpf_io_uring_emit_cqe(ctx, DEFAULT_CQ_IDX, CONTEXT_ERROR, 22222, 0);
            return 0; 
      }  

      ret = bpf_io_uring_reap_cqe(ctx, OPEN_CQ_IDX, &cqe, sizeof(cqe));
      if(cqe.res >= 0)
      {
#ifdef IO_URING_FIXED_FILE
            // context->fixed_fd = context->current_file_idx;
#else      
            context->fd = cqe.res;
#endif
            context->read_offset = 0;

            // bpf_io_uring_emit_cqe(ctx, DEFAULT_CQ_IDX, 1110100, cqe.res, 0);
            // return 0;

      }
      else
      {
            // bpf_io_uring_emit_cqe(ctx, DEFAULT_CQ_IDX, context->fixed_fd, context->current_file_idx, 0);
            bpf_io_uring_emit_cqe(ctx, DEFAULT_CQ_IDX, OPEN_ERROR, cqe.res, 0);
            return 0;
      }

#ifdef IO_URING_FIXED_FILE
      io_uring_prep_rw(IORING_OP_READ, &sqe, context->fixed_fd, context->buffer_userspace_ptr, BUFFER_SIZE, context->read_offset);
      sqe.cq_idx = READ_CQ_IDX;
      sqe.user_data = 9014;
      sqe.flags = IOSQE_IO_HARDLINK | IOSQE_FIXED_FILE;
      bpf_io_uring_submit(ctx, &sqe, sizeof(sqe));
#else
      io_uring_prep_rw(IORING_OP_READ, &sqe, context->fd, context->buffer_userspace_ptr, BUFFER_SIZE, context->read_offset);
      sqe.cq_idx = READ_CQ_IDX;
      sqe.user_data = 9014;
      sqe.flags = IOSQE_IO_HARDLINK;
      bpf_io_uring_submit(ctx, &sqe, sizeof(sqe));
#endif

      io_uring_prep_bpf(&sqe, READ_PROG_IDX, 0);  
      sqe.cq_idx = SINK_CQ_IDX;
      sqe.user_data = 2004;
      bpf_io_uring_submit(ctx, &sqe, sizeof(sqe));

      return 0;
}

SEC("iouring")
int read_callback(struct io_uring_bpf_ctx *ctx)
{
      struct io_uring_sqe sqe;
	struct io_uring_cqe cqe;
      uint32_t key = 0;
      int ret;
      ebpf_context_t *context;

      context = (ebpf_context_t *) bpf_map_lookup_elem(&context_map, &key); 
      if(!context)
      {
            bpf_io_uring_emit_cqe(ctx, DEFAULT_CQ_IDX, CONTEXT_ERROR, 22222, 0);
            return 0; 
      }

      // iouring_reap_cqe(ctx, SINK_CQ_IDX, &cqe, sizeof(cqe));

      ret = bpf_io_uring_reap_cqe(ctx, READ_CQ_IDX, &cqe, sizeof(cqe));
      if (cqe.res > 0)
      {
            // iouring_emit_cqe(ctx, DEFAULT_CQ_IDX, 22222, 22222, 0);

            context->read_offset += cqe.res;
            context->nr_of_bytes_to_write = cqe.res; // TODO: Necessary?!

            
#ifdef IO_URING_FIXED_FILE
            io_uring_prep_rw(IORING_OP_WRITE, &sqe, STDOUT_FILENO_FIX, context->buffer_userspace_ptr, cqe.res, context->write_offset);
            sqe.cq_idx = WRITE_CQ_IDX;
            sqe.user_data = 98787;
            sqe.flags = IOSQE_IO_HARDLINK | IOSQE_FIXED_FILE;
            bpf_io_uring_submit(ctx, &sqe, sizeof(sqe));
#else
            io_uring_prep_rw(IORING_OP_WRITE, &sqe, STDOUT_FILENO, context->buffer_userspace_ptr, cqe.res, context->write_offset);
            sqe.cq_idx = WRITE_CQ_IDX;
            sqe.user_data = 98787;
            sqe.flags = IOSQE_IO_HARDLINK;
            bpf_io_uring_submit(ctx, &sqe, sizeof(sqe));
#endif

            io_uring_prep_bpf(&sqe, WRITE_PROG_IDX, 0);
            sqe.cq_idx = SINK_CQ_IDX;
            sqe.user_data = 2004;
            bpf_io_uring_submit(ctx, &sqe, sizeof(sqe));

            // context->write_offset += cqe.res; //TODO: Eigtl erst nachem der write-call zurückgekehrt ist. Sollte aber eigtl. auch so klappen.
      }
      else if (cqe.res == 0) //end of file
      {
            context->current_file_idx++;
#ifdef IO_URING_FIXED_FILE
            if (context->current_file_idx == context->nr_of_files) //Done, only end program when last file is closed
            {
                  bpf_io_uring_emit_cqe(ctx, DEFAULT_CQ_IDX, CAT_COMPLETE, 22222, 0);
            }
            else //Open new file
            {
                  // bpf_io_uring_emit_cqe(ctx, DEFAULT_CQ_IDX, 44444, context->current_file_idx, 0);
                  io_uring_prep_openat(&sqe, AT_FDCWD, context->paths_userspace_ptr[context->current_file_idx & (MAX_FDS - 1)], O_RDONLY, S_IRUSR | S_IWUSR);
                  sqe.cq_idx = OPEN_CQ_IDX;
                  sqe.user_data = 6879;
                  sqe.flags = IOSQE_IO_HARDLINK;

                  sqe.file_index = context->current_file_idx + 1; // codiert als +1 in uring. Haben keine Funktionen hier die das schon machen => selber 1 addieren.
                  bpf_io_uring_submit(ctx, &sqe, sizeof(sqe));

                  io_uring_prep_bpf(&sqe, OPEN_PROG_IDX, 0);
                  sqe.cq_idx = SINK_CQ_IDX;
                  sqe.user_data = 2004;
                  bpf_io_uring_submit(ctx, &sqe, sizeof(sqe));
            }
#endif

            // iouring_emit_cqe(ctx, DEFAULT_CQ_IDX, 33333, 33333, 0);
#ifndef IO_URING_FIXED_FILE
            io_uring_prep_close(&sqe, context->fd);
            sqe.cq_idx = CLOSE_CQ_IDX;
            sqe.user_data = 587;
            sqe.flags = IOSQE_IO_HARDLINK;
            bpf_io_uring_submit(ctx, &sqe, sizeof(sqe));

            io_uring_prep_bpf(&sqe, CLOSE_PROG_IDX, 0);
            sqe.cq_idx = SINK_CQ_IDX;
            sqe.user_data = 2004;
            bpf_io_uring_submit(ctx, &sqe, sizeof(sqe));
#endif
      }
      else //error read-sqe
      {
            bpf_io_uring_emit_cqe(ctx, DEFAULT_CQ_IDX, READ_ERROR, cqe.res, 0);
      }

      return 0;
}

SEC("iouring") 
int write_callback(struct io_uring_bpf_ctx *ctx)
{
      struct io_uring_sqe sqe;
	struct io_uring_cqe cqe;
      uint32_t key = 0;
      int ret;
      ebpf_context_t *context;

      context = (ebpf_context_t *) bpf_map_lookup_elem(&context_map, &key); 
      if(!context)
      {
            bpf_io_uring_emit_cqe(ctx, DEFAULT_CQ_IDX, CONTEXT_ERROR, 22222, 0);
            return 0; 
      }

      ret = bpf_io_uring_reap_cqe(ctx, WRITE_CQ_IDX, &cqe, sizeof(cqe));
      if (cqe.res > 0)
      {
            context->write_offset += cqe.res;
            // nr_of_write_repeats = 0;
      }
      else
      {
            bpf_io_uring_emit_cqe(ctx, DEFAULT_CQ_IDX, WRITE_ERROR, cqe.res, 0);
            // iouring_emit_cqe(ctx, DEFAULT_CQ_IDX, WRITE_ERROR, nr_of_write_repeats, 0);
            return 0;
      }
#ifdef IO_URING_FIXED_FILE
      io_uring_prep_rw(IORING_OP_READ, &sqe, context->fixed_fd, context->buffer_userspace_ptr, BUFFER_SIZE, context->read_offset);
      sqe.cq_idx = READ_CQ_IDX;
      sqe.user_data = 9014;
      sqe.flags = IOSQE_IO_HARDLINK | IOSQE_FIXED_FILE;
      bpf_io_uring_submit(ctx, &sqe, sizeof(sqe));
#else
      io_uring_prep_rw(IORING_OP_READ, &sqe, context->fd, context->buffer_userspace_ptr, BUFFER_SIZE, context->read_offset);
      sqe.cq_idx = READ_CQ_IDX;
      sqe.user_data = 9014;
      sqe.flags = IOSQE_IO_HARDLINK;
      bpf_io_uring_submit(ctx, &sqe, sizeof(sqe));
#endif

      io_uring_prep_bpf(&sqe, READ_PROG_IDX, 0);  
      sqe.cq_idx = SINK_CQ_IDX;
      sqe.user_data = 2004;
      bpf_io_uring_submit(ctx, &sqe, sizeof(sqe));

      return 0;
}

SEC("iouring")
int close_callback(struct io_uring_bpf_ctx *ctx)
{
      struct io_uring_sqe sqe;
	struct io_uring_cqe cqe;
      uint32_t key = 0;
      ebpf_context_t *context;

      context = (ebpf_context_t *) bpf_map_lookup_elem(&context_map, &key); 
      if(!context)
      {
            bpf_io_uring_emit_cqe(ctx, DEFAULT_CQ_IDX, CONTEXT_ERROR, 22222, 0);
            return 0; 
      }

      int ret = bpf_io_uring_reap_cqe(ctx, CLOSE_CQ_IDX, &cqe, sizeof(cqe));

      if (cqe.res != 0)
      {
            bpf_io_uring_emit_cqe(ctx, DEFAULT_CQ_IDX, CLOSE_LAST_FILE_ERROR, cqe.res, 0);
      }
      else if (context->current_file_idx == context->nr_of_files) //Done, only end program when last file is closed
      {
            bpf_io_uring_emit_cqe(ctx, DEFAULT_CQ_IDX, CAT_COMPLETE, 22222, 0);
      }
      else //Open new file
      {
            // bpf_io_uring_emit_cqe(ctx, DEFAULT_CQ_IDX, 44444, context->current_file_idx, 0);
            io_uring_prep_openat(&sqe, AT_FDCWD, context->paths_userspace_ptr[context->current_file_idx & (MAX_FDS - 1)], O_RDONLY, S_IRUSR | S_IWUSR);
            sqe.cq_idx = OPEN_CQ_IDX;
            sqe.user_data = 6879;
            sqe.flags = IOSQE_IO_HARDLINK;
#ifdef IO_URING_FIXED_FILE
            sqe.file_index = context->current_file_idx + 1;
#endif
            bpf_io_uring_submit(ctx, &sqe, sizeof(sqe));

            io_uring_prep_bpf(&sqe, OPEN_PROG_IDX, 0);
            sqe.cq_idx = SINK_CQ_IDX;
            sqe.user_data = 2004;
            bpf_io_uring_submit(ctx, &sqe, sizeof(sqe));
      }

      return 0;
}

char _license[] SEC("license") = "GPL";