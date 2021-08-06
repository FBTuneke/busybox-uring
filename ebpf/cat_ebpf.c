#include <inttypes.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "../include/cat_common.h"
#include "../../linux/tools/lib/bpf/bpf_helpers.h"
#include <sys/socket.h>
#include <unistd.h>

struct bpf_map_def SEC("maps") context_map =
{
        .type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof(uint32_t),
        .value_size = sizeof(ebpf_context_t),
        .max_entries = 1,
        .map_flags = BPF_F_MMAPABLE,
};

static long (*iouring_queue_sqe)(void *bpf_ctx, struct io_uring_sqe *sqe, uint32_t sqe_len) = (void *) 164;
static long (*iouring_emit_cqe)(void *bpf_ctx, uint32_t cq_idx, __u64 user_data, int res, uint32_t flags) = (void *) 165;
static long (*iouring_reap_cqe)(void *bpf_ctx, uint32_t cq_idx, struct io_uring_cqe *cqe_out, uint32_t cqe_len) = (void *) 166;
// static long (*bpf_custom_copy_to_user)(void *user_ptr, const void *src, __u32 size) = (void *) 167; //overwrite normal bpf_copy_to_user
static unsigned long (*bpf_memchr)(void *src, ssize_t size, int c) = (void *) 168;

static inline void io_uring_prep_rw(int op, struct io_uring_sqe *sqe, int fd,const void *addr, unsigned len, __u64 offset)
{
	sqe->opcode = op;
	sqe->flags = 0;
	sqe->ioprio = 0;
	sqe->fd = fd;
	sqe->off = offset;
	sqe->addr = (unsigned long) addr;
	sqe->len = len;
	sqe->rw_flags = 0;
	sqe->user_data = 0;
	sqe->__pad2[0] = sqe->__pad2[1] = sqe->__pad2[2] = 0;
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

SEC("iouring.s/cat") //.s = .is_sleepable = true
int cat(struct io_uring_bpf_ctx *ctx)
{
      struct io_uring_sqe sqe;
	struct io_uring_cqe cqe = {};
      uint32_t key = 0;
      int ret;
      ebpf_context_t *context;

      context = (ebpf_context_t *) bpf_map_lookup_elem(&context_map, &key); 
      if(!context)
      {
            iouring_emit_cqe(ctx, DEFAULT_CQ_IDX, CONTEXT_ERROR, 22222, 0); //Aus Kernelmodus zurückkehren und printen
            return 0; 
      }
 
      ret = iouring_reap_cqe(ctx, OPEN_CQ_IDX, &cqe, sizeof(cqe));
      if(ret)
      {     
            context->fd = cqe.res;
            context->offset = 0;

            // iouring_emit_cqe(ctx, DEFAULT_CQ_IDX, cqe.res, 777777, 0);
            // return 0;
      }
      else
      {
            iouring_emit_cqe(ctx, DEFAULT_CQ_IDX, OPEN_CQ_ERROR, 22222, 0);
            return 0;
      }

      //Neues Feature auf CQs warten.
      ctx->wait_nr = 1;

      for(int i = 0; i < MAX_LOOP; i++)
      {
            io_uring_prep_rw(IORING_OP_READ, &sqe, context->fd, context->buffer_userspace_ptr, BUFFER_SIZE, context->offset);
            sqe.cq_idx = READ_CQ_IDX;
            sqe.user_data = 9014;
            iouring_queue_sqe(ctx, &sqe, sizeof(sqe));

            ctx->wait_idx = READ_CQ_IDX;

            ret = iouring_reap_cqe(ctx, READ_CQ_IDX, &cqe, sizeof(cqe));
            if(!ret)
            {
                  iouring_emit_cqe(ctx, DEFAULT_CQ_IDX, READ_CQ_ERROR, 22222, 0);
                  return 0;
            }

            if(cqe.res > 0) 
            {
                  io_uring_prep_rw(IORING_OP_WRITE, &sqe, STDIN_FILENO, context->buffer_userspace_ptr, cqe.res, context->offset);
                  sqe.cq_idx = WRITE_CQ_IDX;
                  sqe.user_data = 9014;
                  iouring_queue_sqe(ctx, &sqe, sizeof(sqe));
                  context->offset += cqe.res;

                  // ctx->wait_idx = WRITE_CQ_IDX;

                  // ret = iouring_reap_cqe(ctx, WRITE_CQ_IDX, &cqe, sizeof(cqe));
                  // if(!ret)
                  // {
                  //       iouring_emit_cqe(ctx, DEFAULT_CQ_IDX, READ_CQ_ERROR, 22222, 0);
                  //       return 0;
                  // }
            }
            else if (cqe.res == 0) //Dateiende
            {
                  context->current_file_idx++;
                  
                  io_uring_prep_close(&sqe, context->fd);
                  sqe.cq_idx = SINK_CQ_IDX;
			sqe.user_data = 587;
                  iouring_queue_sqe(ctx, &sqe, sizeof(sqe));
                  
                  if(context->current_file_idx == context->nr_of_files) //Fertig.
                  {
                        iouring_emit_cqe(ctx, DEFAULT_CQ_IDX, CAT_COMPLETE, 22222, 0);
                        return 0;
                  }
                  else //TODO: Könnte hier auch in der Loop bleiben - würde dann          
                  {
                        io_uring_prep_openat(&sqe, 0, context->paths_userspace_ptr[context->current_file_idx], O_RDONLY, 0); 
                        sqe.cq_idx = OPEN_CQ_IDX;
                        sqe.user_data = 6879;
                        sqe.flags = IOSQE_IO_HARDLINK;
                        iouring_queue_sqe(ctx, &sqe, sizeof(sqe));

                        // io_uring_prep_bpf(&sqe, CAT_PROG_IDX, 0);  
                        // sqe.cq_idx = SINK_CQ_IDX;
                        // sqe.user_data = 2004;
                        // iouring_queue_sqe(ctx, &sqe, sizeof(sqe));

                        break;
                  }
            }
            else
            {
                  iouring_emit_cqe(ctx, DEFAULT_CQ_IDX, READ_ERROR, 22222, 0);
                  return 0;
            }
      }// End Loop

      io_uring_prep_bpf(&sqe, CAT_PROG_IDX, 0);  
      sqe.cq_idx = SINK_CQ_IDX;
      sqe.user_data = 2004;
      iouring_queue_sqe(ctx, &sqe, sizeof(sqe));

      return 0;
}