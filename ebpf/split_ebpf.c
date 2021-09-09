#include <inttypes.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "../include/split_common.h"
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

// static long (*bpf_io_uring_submit)(void *bpf_ctx, struct io_uring_sqe *sqe, uint32_t sqe_len) = (void *) 170;
// static long (*bpf_io_uring_emit_cqe)(void *bpf_ctx, uint32_t cq_idx, __u64 user_data, int res, uint32_t flags) = (void *) 171;
// static long (*bpf_io_uring_reap_cqe)(void *bpf_ctx, uint32_t cq_idx, struct io_uring_cqe *cqe_out, uint32_t cqe_len) = (void *) 172;
// static long (*bpf_custom_copy_to_user)(void *user_ptr, const void *src, __u32 size) = (void *) 167; //overwrite normal bpf_copy_to_user
static unsigned long (*bpf_memchr)(void *src, ssize_t size, int c) = (void *) 173;

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

uint32_t bytes_read = 0;
uint32_t to_write = 0;
uint32_t offset_read = 0;
uint32_t offset_write = 0;
off_t remaining = 0;
int fd;
// char *read_buffer_kernelspace_ptr, *read_buffer_userspace_ptr;
uint32_t global_read_buffer_offset = 0;
int cnt = 0;

SEC("iouring")
int split(struct io_uring_bpf_ctx *ctx)
{
      struct io_uring_sqe sqe;
	struct io_uring_cqe cqe;
      uint32_t key = 0;
      int ret;
      ebpf_context_t *context;

      context = (ebpf_context_t *) bpf_map_lookup_elem(&context_map, &key); 
      if(!context)
      {
            bpf_io_uring_emit_cqe(ctx, DEFAULT_CQ_IDX, 27, 277, 0); //Aus Kernelmodus zurückkehren
            return 0;  
      } 
      // pfx = context->pfx_buffer; 

      cnt++;
      // iouring_emit_cqe(ctx, DEFAULT_CQ_IDX, cnt, 111111, 0);


      ret = bpf_io_uring_reap_cqe(ctx, READ_CQ_IDX, &cqe, sizeof(cqe));
      if(ret == 0) //Erfolg, cqe war da!
      {
            bytes_read = cqe.res;
            // read_buffer_kernelspace_ptr = context->read_buffer;
            // read_buffer_userspace_ptr = context->read_buffer_userspace_base_ptr;
            context->read_buffer_base_int = (longword)context->read_buffer; //TODO: Nur ein mal im Userspace machen.
            global_read_buffer_offset = 0;
            offset_read += cqe.res;
      }
      
      if(bytes_read > 0)
      {
            ret = bpf_io_uring_reap_cqe(ctx, OPEN_CQ_IDX, &cqe, sizeof(cqe));
            // iouring_emit_cqe(ctx, DEFAULT_CQ_IDX, cqe.res, 111111, 0);
            if(ret == 0) //Erfolg, cqe war da!
            {
                  fd = cqe.res;

                  // pfx = next_file(pfx, context->suffix_len, context->pfx_len);
//==========next_file() begin. Kann ich nicht als Funktion implementieren, Zeigerarithmetik mit "normalem" Stack-Zeiger gefaellt dem Verifier nicht.
                  int backwards_index;
                  for (int i = 1; i < NAME_MAX; i++)
                  {
                        backwards_index = context->pfx_len - i;
                        if (context->pfx_buffer[backwards_index & NAME_MAX] < 'z')
                        {
                              context->pfx_buffer[backwards_index & NAME_MAX] += 1;
                              break;
                        }

                        if (i + 1 > context->suffix_len) //Filenamen aufgebraucht!
                        {
                              return 0;
                              bpf_io_uring_emit_cqe(ctx, DEFAULT_CQ_IDX, SUFFIX_EXHAUSTED, 11187, 0);
                        }

                        context->pfx_buffer[backwards_index & NAME_MAX] = 'a';
                  }
//==========next_file() end

                  remaining = context->cnt;
                  offset_write = 0;
            }

            for(int i = 0; i < READ_BUFFER_SIZE; i++) //Im schlechtesten Fall 1 Byte pro Zeile. Bounded Loop für Verifier..
            {            
                  if (!remaining) 
			{
				// if (!pfx) //suffixes exhausted -- 16.07.2021: ist jetzt oben in der Schleife von "next_file"-Funktionalitaet
                        // {
                        //        //Aus Kernelmodus zurückkehren und printen
                        // }

                        context->fixed_fd++;

#ifndef IO_URING_FIXED_FILE
                        io_uring_prep_close(&sqe, fd); //TODO: vllt callback für close?
                        sqe.cq_idx = SINK_CQ_IDX;
                        sqe.flags = IOSQE_IO_HARDLINK;
				sqe.user_data = 187;
				bpf_io_uring_submit(ctx, &sqe, sizeof(sqe));
#endif
                        
                        io_uring_prep_openat(&sqe, AT_FDCWD, context->pfx_buffer_userspace_base_ptr, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
                        sqe.cq_idx = OPEN_CQ_IDX;
                        sqe.user_data = 6879;
                        sqe.flags = IOSQE_IO_HARDLINK; //Draining does not seem to work. --> Neue Kette
#ifdef IO_URING_FIXED_FILE
                        sqe.file_index = context->fixed_fd + 1; //encoded as index + 1
#endif
                        bpf_io_uring_submit(ctx, &sqe, sizeof(sqe));
				
                        io_uring_prep_bpf(&sqe, SPLIT_PROG, 0);  
                        sqe.cq_idx = SINK_CQ_IDX;
                        sqe.user_data = 2004;
                        // sqe.flags = IOSQE_IO_HARDLINK;
                        bpf_io_uring_submit(ctx, &sqe, sizeof(sqe));

                        return 0;
			}

                  uint64_t end = bpf_memchr(&context->read_buffer[global_read_buffer_offset & (READ_BUFFER_SIZE - 1)], bytes_read, '\n');

                  if (end) //Zeilenende gefunden
                  {
                        --remaining;
                        // to_write = (char*)char_ptr - read_buffer_kernelspace_ptr + 1;
                        // to_write = bytes_read - (n - 1);
                        // to_write = n;
                        to_write = end - (context->read_buffer_base_int + global_read_buffer_offset) + 1;
                        // return 0;
                  }
                  else
                  {
                        to_write = bytes_read;
                  }

                  // iouring_emit_cqe(ctx, DEFAULT_CQ_IDX, fd, 111111, 0);

#ifdef IO_URING_FIXED_FILE
                  io_uring_prep_rw(IORING_OP_WRITE, &sqe, context->fixed_fd, context->read_buffer_userspace_base_ptr + global_read_buffer_offset, to_write, offset_write);
                  sqe.flags = IOSQE_IO_HARDLINK | IOSQE_FIXED_FILE;  
#else
                  io_uring_prep_rw(IORING_OP_WRITE, &sqe, fd, context->read_buffer_userspace_base_ptr + global_read_buffer_offset, to_write, offset_write);
                  sqe.flags = IOSQE_IO_HARDLINK;                 
#endif
                  sqe.cq_idx = SINK_CQ_IDX;
                  sqe.user_data = 1014;
                  bpf_io_uring_submit(ctx, &sqe, sizeof(sqe));        

			bytes_read -= to_write;
                  global_read_buffer_offset += to_write;
			// read_buffer_kernelspace_ptr += to_write;
                  // read_buffer_userspace_ptr += to_write;
			offset_write += to_write;
      
                  if(!bytes_read)
                        break;
            }
#ifdef IO_URING_FIXED_FILE
            io_uring_prep_rw(IORING_OP_READ, &sqe, STDIN_FILENO_FIX, context->read_buffer_userspace_base_ptr, READ_BUFFER_SIZE, offset_read);
            sqe.flags = IOSQE_IO_HARDLINK | IOSQE_FIXED_FILE;
#else
            io_uring_prep_rw(IORING_OP_READ, &sqe, STDIN_FILENO, context->read_buffer_userspace_base_ptr, READ_BUFFER_SIZE, offset_read);
            sqe.flags = IOSQE_IO_HARDLINK; //Muss bleiben und nach den Writes kommen
#endif      
            sqe.cq_idx = READ_CQ_IDX;
            sqe.user_data = 9014;
            bpf_io_uring_submit(ctx, &sqe, sizeof(sqe));

            io_uring_prep_bpf(&sqe, SPLIT_PROG, 0);  
            sqe.cq_idx = SINK_CQ_IDX;
            if(!remaining) sqe.flags = IOSQE_IO_HARDLINK;
            sqe.user_data = 9004;
            // sqe.flags = IOSQE_IO_DRAIN;
            bpf_io_uring_submit(ctx, &sqe, sizeof(sqe));

            // Fall: Buffer zu Ende gelesen und Datei zu Ende geschrieben. Tritt dies auf, dann greift die obere Abfrage (olFd != fd) nicht, da fd erst in dem n�chsten
		// Schleifendurchlauf ge�ndert werden w�rde, den es aber nicht mehr gibt. Also muss hier noch mal geclosed werden.
		if(!remaining) 
		{
#ifndef IO_URING_FIXED_FILE
                  io_uring_prep_close(&sqe, fd); //TODO: vllt callback für close?
                  sqe.cq_idx = SINK_CQ_IDX;
                  // sqe.flags = IOSQE_IO_HARDLINK; //Muss bleiben,
			sqe.user_data = 587;
                  bpf_io_uring_submit(ctx, &sqe, sizeof(sqe));
#endif

                  // //Optimierung: Hier schonmal auf Verdacht aufmachen - muss dann unten im else-Zweig aber auch geschlossen werden.
                  // io_uring_prep_openat(&sqe, AT_FDCWD, context->pfx_buffer_userspace_base_ptr, O_WRONLY | O_CREAT | O_TRUNC, S_IRWXU);
                  // sqe.cq_idx = OPEN_CQ_IDX;
                  // sqe.flags = IOSQE_IO_DRAIN; 
                  // sqe.user_data = 4778;
                  // iouring_queue_sqe(ctx, &sqe, sizeof(sqe));
		}

            return 0;

      }
      else
      {
            bpf_io_uring_emit_cqe(ctx, DEFAULT_CQ_IDX, SPLIT_COMPLETE, 22222, 0); //Aus Kernelmodus zurückkehren und printen
      }

      return 0;
}