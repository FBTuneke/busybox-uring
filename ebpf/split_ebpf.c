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

static long (*iouring_queue_sqe)(void *bpf_ctx, struct io_uring_sqe *sqe, uint32_t sqe_len) = (void *) 164;
static long (*iouring_emit_cqe)(void *bpf_ctx, uint32_t cq_idx, __u64 user_data, int res, uint32_t flags) = (void *) 165;
static long (*iouring_reap_cqe)(void *bpf_ctx, uint32_t cq_idx, struct io_uring_cqe *cqe_out, uint32_t cqe_len) = (void *) 166;
static long (*bpf_custom_copy_to_user)(void *user_ptr, const void *src, __u32 size) = (void *) 167; //overwrite normal bpf_copy_to_user
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

/* Increment the suffix part of the filename.
 * Returns NULL if we are out of filenames.
 */
// static inline char *next_file(char *old, unsigned suffix_len, unsigned pfx_len)
// {
// 	size_t end = pfx_len;
// 	char *curr;

//       for(int i = 1; i < NAME_MAX; i++)
//       {
//             curr = old + end - i;
// 		if (*curr < 'z') 
//             {
// 			*curr += 1;
// 			break;
// 		}

//             if (i + 1 > suffix_len)
// 		      return NULL;

// 		*curr = 'a';
//       }

// 	return old;
// }

// static inline void *memchr(void const *s, int c_in, size_t n)
// {
//       /* On 32-bit hardware, choosing longword to be a 32-bit unsigned
//      long instead of a 64-bit uintmax_t tends to give better
//      performance.  On 64-bit hardware, unsigned long is generally 64
//      bits already.  Change this typedef to experiment with
//      performance.  */
//       typedef unsigned long int longword;
//       const unsigned char *char_ptr;
//       const longword *longword_ptr;
//       longword repeated_one;
//       longword repeated_c;
//       unsigned char c;
//       c = (unsigned char)c_in;
//       /* Handle the first few bytes by reading one byte at a time.
//      Do this until CHAR_PTR is aligned on a longword boundary.  */
//       for (char_ptr = (const unsigned char *)s;
//            n > 0 && (size_t)char_ptr % sizeof(longword) != 0;
//            --n, ++char_ptr)
//             if (*char_ptr == c)
//                   return (void *)char_ptr;
//       longword_ptr = (const longword *)char_ptr;
//       /* All these elucidatory comments refer to 4-byte longwords,
//      but the theory applies equally well to any size longwords.  */
//       /* Compute auxiliary longword values:
//      repeated_one is a value which has a 1 in every byte.
//      repeated_c has c in every byte.  */
//       repeated_one = 0x01010101;
//       repeated_c = c | (c << 8);
//       repeated_c |= repeated_c << 16;
//       if (0xffffffffU < (longword)-1)
//       {
//             repeated_one |= repeated_one << 31 << 1;
//             repeated_c |= repeated_c << 31 << 1;
//             if (8 < sizeof(longword))
//             {
//                   size_t i;
//                   for (i = 64; i < sizeof(longword) * 8; i *= 2)
//                   {
//                         repeated_one |= repeated_one << i;
//                         repeated_c |= repeated_c << i;
//                   }
//             }
//       }
//       /* Instead of the traditional loop which tests each byte, we will test a
//      longword at a time.  The tricky part is testing if *any of the four*
//      bytes in the longword in question are equal to c.  We first use an xor
//      with repeated_c.  This reduces the task to testing whether *any of the
//      four* bytes in longword1 is zero.
//      We compute tmp =
//        ((longword1 - repeated_one) & ~longword1) & (repeated_one << 7).
//      That is, we perform the following operations:
//        1. Subtract repeated_one.
//        2. & ~longword1.
//        3. & a mask consisting of 0x80 in every byte.
//      Consider what happens in each byte:
//        - If a byte of longword1 is zero, step 1 and 2 transform it into 0xff,
//          and step 3 transforms it into 0x80.  A carry can also be propagated
//          to more significant bytes.
//        - If a byte of longword1 is nonzero, let its lowest 1 bit be at
//          position k (0 <= k <= 7); so the lowest k bits are 0.  After step 1,
//          the byte ends in a single bit of value 0 and k bits of value 1.
//          After step 2, the result is just k bits of value 1: 2^k - 1.  After
//          step 3, the result is 0.  And no carry is produced.
//      So, if longword1 has only non-zero bytes, tmp is zero.
//      Whereas if longword1 has a zero byte, call j the position of the least
//      significant zero byte.  Then the result has a zero at positions 0, ...,
//      j-1 and a 0x80 at position j.  We cannot predict the result at the more
//      significant bytes (positions j+1..3), but it does not matter since we
//      already have a non-zero bit at position 8*j+7.
//      So, the test whether any byte in longword1 is zero is equivalent to
//      testing whether tmp is nonzero.  */
//       while (n >= sizeof(longword))
//       {
//             longword longword1 = *longword_ptr ^ repeated_c;
//             if ((((longword1 - repeated_one) & ~longword1) & (repeated_one << 7)) != 0)
//                   break;
//             longword_ptr++;
//             n -= sizeof(longword);
//       }
//       char_ptr = (const unsigned char *)longword_ptr;
//       /* At this point, we know that either n < sizeof (longword), or one of the
//      sizeof (longword) bytes starting at char_ptr is == c.  On little-endian
//      machines, we could determine the first such byte without any further
//      memory accesses, just by looking at the tmp result from the last loop
//      iteration.  But this does not work on big-endian machines.  Choose code
//      that works in both cases.  */
//       for (; n > 0; --n, ++char_ptr)
//       {
//             if (*char_ptr == c)
//                   return (void *)char_ptr;
//       }
//       return NULL;
// }

uint32_t bytes_read = 0;
uint32_t to_write = 0;
uint32_t offset_read = 0;
uint32_t offset_write = 0;
off_t remaining = 0;
bool fds_need_to_be_set = true;
int fd, old_fd;
// char *read_buffer_kernelspace_ptr, *read_buffer_userspace_ptr;
uint32_t global_read_buffer_offset = 0;

SEC("iouring.s/split") //.s = .is_sleepable = true
int split(struct io_uring_bpf_ctx *ctx)
{
      struct io_uring_sqe sqe;
	struct io_uring_cqe cqe = {};
      uint32_t key = 0;
      int ret;
      ebpf_context_t *context;
      bool complete;

      context = (ebpf_context_t *) bpf_map_lookup_elem(&context_map, &key);  
      if(!context)
      {
            iouring_emit_cqe(ctx, DEFAULT_CQ_IDX, 27, 277, 0); //Aus Kernelmodus zurückkehren
            return 0;  
      } 
      // pfx = context->pfx_buffer; 


      ret = iouring_reap_cqe(ctx, READ_CQ_IDX, &cqe, sizeof(cqe));
      if(ret == 0) //Erfolg, cqe war da!
      {
            bytes_read = cqe.res;
            // read_buffer_kernelspace_ptr = context->read_buffer;
            // read_buffer_userspace_ptr = context->read_buffer_userspace_base_ptr;
            context->read_buffer_base_int = (longword)context->read_buffer; //TODO: Nur ein mal im Userspace machen.
            global_read_buffer_offset = 0;
            offset_read += cqe.res; 
            if(!remaining) 
                  fds_need_to_be_set = true;
      }

      ret = iouring_reap_cqe(ctx, OPEN_CQ_IDX, &cqe, sizeof(cqe));
      if(ret == 0) //Erfolg, cqe war da!
      {
            fd = cqe.res;
            
            if(fds_need_to_be_set)
		{
			fds_need_to_be_set = false;
			old_fd = fd;
		}

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
                        iouring_emit_cqe(ctx, DEFAULT_CQ_IDX, SUFFIX_EXHAUSTED, 11187, 0);
                  }

                  context->pfx_buffer[backwards_index & NAME_MAX] = 'a';
            }
//==========next_file() end

            remaining = context->cnt;
		offset_write = 0;
      }

      if(bytes_read > 0)
      {
            for(int i = 0; i < READ_BUFFER_SIZE; i++) //Im schlechtesten Fall 1 Byte pro Zeile. Bounded Loop für Verifier..
            {            
                  if (!remaining) 
			{
				// if (!pfx) //suffixes exhausted -- 16.07.2021: ist jetzt oben in der Schleife von "next_file"-Funktionalitaet
                        // {
                        //        //Aus Kernelmodus zurückkehren und printen
                        // }

                        io_uring_prep_openat(&sqe, AT_FDCWD, context->pfx_buffer_userspace_base_ptr, O_WRONLY | O_CREAT | O_TRUNC, S_IRWXU);
                        sqe.cq_idx = OPEN_CQ_IDX;
                        sqe.flags = IOSQE_IO_DRAIN; 
                        sqe.user_data = 6879;
                        iouring_queue_sqe(ctx, &sqe, sizeof(sqe));
				
                        io_uring_prep_bpf(&sqe, SPLIT_PROG, 0);  
                        sqe.cq_idx = SINK_CQ_IDX;
                        sqe.user_data = 2004;
                        sqe.flags = IOSQE_IO_DRAIN;
                        iouring_queue_sqe(ctx, &sqe, sizeof(sqe));

                        return 0;
			}

                  uint64_t end = bpf_memchr(&context->read_buffer[global_read_buffer_offset & (READ_BUFFER_SIZE - 1)], bytes_read, '\n');

                  iouring_emit_cqe(ctx, DEFAULT_CQ_IDX, end, 88888, 0);
                  iouring_emit_cqe(ctx, DEFAULT_CQ_IDX, &context->read_buffer[global_read_buffer_offset & (READ_BUFFER_SIZE - 1)], 88888, 0);
                  return 0;
                  // volatile uint64_t char_index = global_read_buffer_index;
                  // volatile uint64_t n = 1;
                  // complete = false;
                  // for(; char_index < 8; char_index++, n++)
                  // {
                  //       if(context->read_buffer[char_index & (READ_BUFFER_SIZE -1)] == '\n')
                  //       {
                  //             complete = true;
                  //             break;
                  //       }
                  // }

// //================start memchr(). Kann ich nicht als Funktion implementieren, Zeigerarithmetik mit "normalem" Stack-Zeiger gefaellt dem Verifier nicht.
                  
//                   /* On 32-bit hardware, choosing longword to be a 32-bit unsigned
//                   long instead of a 64-bit uintmax_t tends to give better
//                   performance.  On 64-bit hardware, unsigned long is generally 64
//                   bits already.  Change this typedef to experiment with
//                   performance.  */                               
//                   size_t n = bytes_read & (READ_BUFFER_SIZE - 1);

//                   uint32_t char_index = global_read_buffer_index, longword_index = global_read_buffer_index, first_longword_boundary_offset;
//                   longword repeated_one;
//                   longword repeated_c;
//                   complete = false;
//                   longword read_buffer_address = context->read_buffer_base_int + global_read_buffer_index; //ARGH! Verifier erlaubt keine modulo-Operation auf Addressen, also erst in Variable speichern..
//                   /* Handle the first few bytes by reading one byte at a time.
//                   Do this until CHAR_PTR is aligned on a longword boundary.  */
                  
//                   for (int i = 0; i < READ_BUFFER_SIZE; --n, ++char_index, read_buffer_address++, i++) //Bounded Loop fuer Verifier...
//                   {
//                         if(n <= 0 || read_buffer_address % sizeof(longword) == 0 || char_index >= READ_BUFFER_SIZE)
//                               break;
            
//                         if (context->read_buffer[char_index] == '\n')
//                         {
//                               complete = true; //Zeichen schon gefunden!
//                               break;
//                         }
//                   }

//                   if(!complete)
//                   {
//                         // longword_ptr = (const longword *)char_ptr;
//                         /* All these elucidatory comments refer to 4-byte longwords,
//                         but the theory applies equally well to any size longwords.  */
//                         /* Compute auxiliary longword values:
//                         repeated_one is a value which has a 1 in every byte.
//                         repeated_c has c in every byte.  */
//                         repeated_one = 0x01010101;
//                         repeated_c = '\n' | ('\n' << 8);
//                         repeated_c |= repeated_c << 16;
//                         if (0xffffffffU < (longword)-1)
//                         {
//                               repeated_one |= repeated_one << 31 << 1;
//                               repeated_c |= repeated_c << 31 << 1;
//                               if (8 < sizeof(longword))
//                               {
//                                     size_t i;
//                                     for (i = 64; i < sizeof(longword) * 8; i *= 2)
//                                     {
//                                           repeated_one |= repeated_one << i;
//                                           repeated_c |= repeated_c << i;
//                                     }
//                               }
//                         }
//                          /* Instead of the traditional loop which tests each byte, we will test a
//                         longword at a time.  The tricky part is testing if *any of the four*
//                         bytes in the longword in question are equal to c.  We first use an xor
//                         with repeated_c.  This reduces the task to testing whether *any of the
//                         four* bytes in longword1 is zero.
//                         We compute tmp =
//                         ((longword1 - repeated_one) & ~longword1) & (repeated_one << 7).
//                         That is, we perform the following operations:
//                         1. Subtract repeated_one.
//                         2. & ~longword1.
//                         3. & a mask consisting of 0x80 in every byte.
//                         Consider what happens in each byte:
//                         - If a byte of longword1 is zero, step 1 and 2 transform it into 0xff,
//                         and step 3 transforms it into 0x80.  A carry can also be propagated
//                         to more significant bytes.
//                         - If a byte of longword1 is nonzero, let its lowest 1 bit be at
//                         position k (0 <= k <= 7); so the lowest k bits are 0.  After step 1,
//                         the byte ends in a single bit of value 0 and k bits of value 1.
//                         After step 2, the result is just k bits of value 1: 2^k - 1.  After
//                         step 3, the result is 0.  And no carry is produced.
//                         So, if longword1 has only non-zero bytes, tmp is zero.
//                         Whereas if longword1 has a zero byte, call j the position of the least
//                         significant zero byte.  Then the result has a zero at positions 0, ...,
//                         j-1 and a 0x80 at position j.  We cannot predict the result at the more
//                         significant bytes (positions j+1..3), but it does not matter since we
//                         already have a non-zero bit at position 8*j+7.
//                         So, the test whether any byte in longword1 is zero is equivalent to
//                         testing whether tmp is nonzero.  */
//                         longword_index = 0;
//                         first_longword_boundary_offset = char_index;
//                         longword longword1;
//                         while (char_index < READ_BUFFER_SIZE) //BOUNDED LOOP FUER VERIFIER
//                         // while (n >= sizeof(longword))
//                         {
//                               if(n < sizeof(longword))
//                                     break;

//                               if(longword_index < READ_BUFFER_SIZE / sizeof(longword) - (read_buffer_address % sizeof(longword) ? 1 : 0))
//                               // longword1 = ((const longword*)context->read_buffer)[longword_index & ((READ_BUFFER_SIZE / sizeof(longword) -1))] ^ repeated_c;
//                                     longword1 = ((const longword*)&context->read_buffer[first_longword_boundary_offset & (READ_BUFFER_SIZE - 1)])[longword_index] ^ repeated_c;

//                               if ((((longword1 - repeated_one) & ~longword1) & (repeated_one << 7)) != 0)
//                                     break;

//                               longword_index++;
//                               char_index += sizeof(longword);
//                               n -= sizeof(longword);
//                         }
//                         // char_ptr = (const unsigned char *)longword_ptr;
//                          /* At this point, we know that either n < sizeof (longword), or one of the
//                         sizeof (longword) bytes starting at char_ptr is == c.  On little-endian
//                         machines, we could determine the first such byte without any further
//                         memory accesses, just by looking at the tmp result from the last loop
//                         iteration.  But this does not work on big-endian machines.  Choose code
//                         that works in both cases.  */
                        
//                         for(; char_index < READ_BUFFER_SIZE; --n, ++char_index)
//                         // for (; n > 0; --n, ++char_index)
//                         {
//                               if(n <= 0)
//                                     break;
                              
//                               if (context->read_buffer[char_index & (READ_BUFFER_SIZE - 1)] == '\n')
//                                     break;
//                               // return (void *)char_ptr;
//                         }
//                   }

//================end memchr()

                  if (end) //Zeilenende gefunden
                  {
                        --remaining;
                        // to_write = (char*)char_ptr - read_buffer_kernelspace_ptr + 1;
                        // to_write = bytes_read - (n - 1);
                        // to_write = n;
                        to_write = end - context->read_buffer_base_int + global_read_buffer_offset + 1;
                  }
                  else
                  {
                        to_write = bytes_read;
                  }

                  //File kann geschlossen werden, wenn neues geoeffnet
			if (old_fd != fd)
			{
				io_uring_prep_close(&sqe, old_fd); //TODO: vllt callback für close?
                        sqe.cq_idx = SINK_CQ_IDX;
                        sqe.flags = IOSQE_IO_DRAIN;
				sqe.user_data = 187;
				iouring_queue_sqe(ctx, &sqe, sizeof(sqe));
				old_fd = fd;
			}

                  io_uring_prep_rw(IORING_OP_WRITE, &sqe, fd, context->read_buffer_userspace_base_ptr + global_read_buffer_offset, to_write, offset_write);
			sqe.cq_idx = SINK_CQ_IDX;
                  sqe.flags = IOSQE_IO_DRAIN;
                  sqe.user_data = 1014;
                  iouring_queue_sqe(ctx, &sqe, sizeof(sqe));

			bytes_read -= to_write;
                  global_read_buffer_offset += to_write;
			// read_buffer_kernelspace_ptr += to_write;
                  // read_buffer_userspace_ptr += to_write;
			offset_write += to_write;

                  if(!bytes_read) break;
            }

            // Fall: Buffer zu Ende gelesen und Datei zu Ende geschrieben. Tritt dies auf, dann greift die obere Abfrage (olFd != fd) nicht, da fd erst in dem n�chsten
		// Schleifendurchlauf ge�ndert werden w�rde, den es aber nicht mehr gibt. Also muss hier noch mal geclosed werden.
		if(!remaining) 
		{
                  io_uring_prep_close(&sqe, fd); //TODO: vllt callback für close?
                  sqe.cq_idx = SINK_CQ_IDX;
                  sqe.flags = IOSQE_IO_DRAIN;
			sqe.user_data = 587;
                  iouring_queue_sqe(ctx, &sqe, sizeof(sqe));

                  io_uring_prep_openat(&sqe, AT_FDCWD, context->pfx_buffer_userspace_base_ptr, O_WRONLY | O_CREAT | O_TRUNC, S_IRWXU);
                  sqe.cq_idx = OPEN_CQ_IDX;
                  sqe.flags = IOSQE_IO_DRAIN; 
                  sqe.user_data = 4778;
                  iouring_queue_sqe(ctx, &sqe, sizeof(sqe));

		}

            io_uring_prep_rw(IORING_OP_READ, &sqe, STDIN_FILENO, context->read_buffer_userspace_base_ptr, READ_BUFFER_SIZE, offset_read);
		sqe.cq_idx = READ_CQ_IDX;
            sqe.flags = IOSQE_IO_DRAIN;
            sqe.user_data = 9014;
            iouring_queue_sqe(ctx, &sqe, sizeof(sqe));

            io_uring_prep_bpf(&sqe, SPLIT_PROG, 0);  
            sqe.cq_idx = SINK_CQ_IDX;
            sqe.user_data = 9004;
            sqe.flags = IOSQE_IO_DRAIN;
            iouring_queue_sqe(ctx, &sqe, sizeof(sqe));

            return 0;

      }
      else
      {
            iouring_emit_cqe(ctx, DEFAULT_CQ_IDX, SPLIT_COMPLETE, 22222, 0); //Aus Kernelmodus zurückkehren und printen
      }

      return 0;
}