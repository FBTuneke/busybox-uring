/* vi: set sw=4 ts=4: */
/*
 * Copyright (C) 2003  Manuel Novoa III  <mjn3@codepoet.org>
 *
 * Licensed under GPLv2, see file LICENSE in this source tree.
 */
//kbuild:lib-y += bb_cat.o

#include "../include/libbb.h"
#include "../include/cat_common.h"
#include "../../linux/tools/lib/bpf/libbpf.h"
#include "../../linux/tools/lib/bpf/bpf.h"
#include "liburing.h"
#include <time.h>
#include <sys/stat.h>

#define NR_OF_BPF_PROGS 2

static void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

      //Noetig, damit Speicher für bpf-Programm + Maps allokiert werden kann. Stand zumindest in einigen "Tutorials"
	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

static int libbpf_print(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static size_t roundup_page(size_t sz)
{
      long page_size = sysconf(_SC_PAGE_SIZE);
      return (sz + page_size - 1) / page_size * page_size;
}

int FAST_FUNC bb_cat(char **argv, int argc)
{
	int ret;
      unsigned int nr_of_files = 0;
      struct io_uring ring;
	struct io_uring_sqe* sqe;
	struct io_uring_cqe* cqe;
      struct io_uring_params params;
      uint32_t cq_sizes[6] = {128, 128, 128, 128, 128, 128};
      struct bpf_object *bpf_obj;
      struct bpf_program *bpf_prog;
      const char *name_object_file, *name;
      uint32_t kversion;
      int prog_fds[NR_OF_BPF_PROGS];
      size_t map_sz;
      void *mmapped_context_map_ptr;
      ebpf_context_t *context_ptr;
      int context_map_fd;

	if (!*argv)
		argv = (char**) &bb_argv_dash;	

      memset(&params, 0, sizeof(params));
      params.nr_cq = ARRAY_SIZE(cq_sizes); //Anzahl von zusätzlichen Completion Queues???
	params.cq_sizes = (__u64)(unsigned long)cq_sizes; //will hier wohl einen Pointer?! 

      if (io_uring_queue_init_params(128, &ring, &params) < 0)
      {
            perror("io_uring_init_failed...\n");
            exit(1);
      }

      if (!(params.features & IORING_FEAT_FAST_POLL))
      {
            printf("IORING_FEAT_FAST_POLL not available in the kernel, quiting...\n");
            exit(0);
      }

      // libbpf_set_print(libbpf_print); //setze libbpf error und debug callback
      bump_memlock_rlimit();

      struct timeval begin, end;
      gettimeofday(&begin, 0);

      bpf_obj = bpf_object__open("/mnt/busybox-uring/cat_ebpf.o");
      // bpf_obj = bpf_object__open("cat_ebpf.o");

      ret = bpf_object__load(bpf_obj);
      if(ret < 0)
      {
            printf("Error bpf_object__load, ret: %i\n", ret);
            return -1;
      }

      gettimeofday(&end, 0);
      long seconds = end.tv_sec - begin.tv_sec;
      long microseconds = end.tv_usec - begin.tv_usec;
      double time_spent_loading_bpf_prog = seconds + microseconds*1e-6;

      name_object_file = bpf_object__name(bpf_obj); //HIER KOMMT DER NAME VOM .o-FILE RAUS. ALSO BEI "ebpf.o" gibt die Funktion "ebpf" zurück.
      // printf("name_object_file: %s\n", name_object_file);

      kversion = bpf_object__kversion(bpf_obj);
      // printf("kversion: %i\n", kversion);

      for(int i = 0; i < NR_OF_BPF_PROGS; i++)
      {
            if(i == 0) bpf_prog = bpf_program__next(NULL, bpf_obj);
            else bpf_prog = bpf_program__next(bpf_prog, bpf_obj);

            name = bpf_program__name(bpf_prog);
            // printf("program %i name: %s\n", i, name);
            name = bpf_program__section_name(bpf_prog);
            // printf("program %i section name: %s\n", i, name);          

            prog_fds[i] = bpf_program__fd(bpf_prog);
            // printf("bpf-program %i fd: %i\n", i, prog_fds[i]);
      } 

      context_map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "context_map");
      // printf("context map fd: %i\n", context_map_fd);
   
      map_sz = roundup_page(1 * sizeof(ebpf_context_t));
      mmapped_context_map_ptr = mmap(NULL, map_sz, PROT_READ | PROT_WRITE, MAP_SHARED, context_map_fd, 0);
      if (mmapped_context_map_ptr == MAP_FAILED || !mmapped_context_map_ptr)
      {
            printf("mmap context map error \n");
            return -1;
      }
      context_ptr = (ebpf_context_t*) mmapped_context_map_ptr;

      //TODO: Durch argc ersetzen - ist aber unused in cat.c? - Rausfinden ob ich das einfach ändern oder sogar direkt benutzen kann.
      for(int i = 0; i < argc - 1; i++)
      {
            if(!*argv || argc >= MAX_FDS)
                  break;
            context_ptr->paths_userspace_ptr[i] = argv[i];
            // printf("argv[%i]: %s\n", i, argv[i]);
            // printf("Address of argv[%i]: %llu\n", i, (unsigned long) argv[i]);
      }

      // printf("argc: %i\n", argc);
      context_ptr->nr_of_files = argc - 1;
      context_ptr->buffer_userspace_ptr = context_ptr->buffer;

      // ret = __sys_io_uring_register(ring.ring_fd, IORING_REGISTER_BPF, prog_fds, NR_OF_BPF_PROGS);
      ret = syscall(427, ring.ring_fd, IORING_REGISTER_BPF, prog_fds, NR_OF_BPF_PROGS); //Ist mir zu nervig das hier ordentlich einzubinden gerade.. scheiss Makefile.
      if(ret < 0)
      {
            printf("Error __sys_io_uring_register, ret: %i\n", ret);
            return -1;
      }

      gettimeofday(&begin, 0);
      sqe = io_uring_get_sqe(&ring);
      if (!sqe)
      {
            printf("get sqe #2 failed\n");
            return -1;
      }
      // printf("argv: %s\n", *argv);
      io_uring_prep_openat(sqe, AT_FDCWD, *argv, O_RDONLY, S_IRUSR | S_IWUSR);
      sqe->user_data = 125;
      sqe->flags = IOSQE_IO_HARDLINK;
      sqe->cq_idx = OPEN_CQ_IDX;

      sqe = io_uring_get_sqe(&ring);
      if (!sqe)
      {
            printf("get sqe #3 failed\n");
            return -1;
      }
      io_uring_prep_nop(sqe);
	sqe->off = CAT_PROG_IDX; //Scheint der Index des eBPF-Programms zu sein.
	sqe->opcode = IORING_OP_BPF;
      sqe->user_data = 999;
	sqe->flags = 0;
      sqe->cq_idx = SINK_CQ_IDX;

      ret = io_uring_submit(&ring);
	if (ret <= 0) 
      {
		printf("sqe submit failed: %i\n", ret);
		return -1;
	}

      //printf("\n======START======\n");
      char *fullPath, *fullPath2;
      char *fileName = "/cat-bpf-log.txt";
      char *fileName2 = "/cat-bpf-last-instruction.txt";
      fullPath = malloc(strlen(getenv("HOME") + strlen(fileName)) + 1); // to account for NULL terminator
      fullPath2 = malloc(strlen(getenv("HOME") + strlen(fileName2)) + 1); // to account for NULL terminator
      strcpy(fullPath, getenv("HOME"));
      strcpy(fullPath2, getenv("HOME"));
      strcat(fullPath, fileName);
      strcat(fullPath2, fileName2);
      FILE *f, *f2;
      f = fopen(fullPath, "a");
      // printf("fullpath: %s", fullPath);
      f2 = fopen(fullPath2, "w");
      // printf("fullpath2: %s", fullPath2);
      while(1)
      {
            ret = io_uring_wait_cqe(&ring, &cqe);
            io_uring_cqe_seen(&ring, cqe);
            
            // printf("\ncqe->user_data: %llu\n", cqe->user_data);
            fprintf(f2, "\ncqe->user_data: %llu\n", cqe->user_data);
            // printf("cqe->res: %i\n", cqe->res);
            fprintf(f2, "cqe->res: %i\n", cqe->res);

            rewind(f2);

            if(cqe->user_data == CAT_COMPLETE)
            {
                  break;
            }
      }

      fclose(f2);

      gettimeofday(&end, 0);
      seconds = end.tv_sec - begin.tv_sec;
      microseconds = end.tv_usec - begin.tv_usec;
      double time_spent_cat = seconds + microseconds*1e-6;

      struct bpf_prog_info bpf_info = {};
      uint32_t info_len = sizeof(bpf_info);

      ret = bpf_obj_get_info_by_fd(prog_fds[0], &bpf_info, &info_len);
	if(ret != 0)
            printf("Error bpf_obj_get_info_by_fd(): %i\n", ret);


      //printf("Verbrauchte Zeit fuer das Laden und Oeffnen des BPF-Programms: %.3f in Sekunden\n", time_spent_loading_bpf_prog);
      fprintf(f, "Verbrauchte Zeit fuer das Laden und Oeffnen des BPF-Programms: %.3f in Sekunden\n", time_spent_loading_bpf_prog);      
      //printf("Verbrauchte Zeit fuer das eigentliche cat: %.3f in Sekunden\n", time_spent_cat);
      fprintf(f, "Verbrauchte Zeit für das eigentliche cat: %.3f in Sekunden\n", time_spent_cat);
      // printf("Jited prog instructions: %llu\n", bpf_info.jited_prog_insns);
      // fprintf(f, "Jited prog instructions: %llu\n", bpf_info.jited_prog_insns);
      // printf("Jited prog length: %u\n", bpf_info.jited_prog_len);
      // fprintf(f, "Jited prog length: %u\n", bpf_info.jited_prog_len);
      // printf("load time (ns since boottime): %llu\n", bpf_info.load_time);
      // fprintf(f, "load time (ns since boottime): %llu\n", bpf_info.load_time);
      // printf("nr func info: %u\n", bpf_info.nr_func_info);
      // fprintf(f, "nr func info: %u\n", bpf_info.nr_func_info);
      // printf("nr jited func lens: %u\n", bpf_info.nr_jited_func_lens);
      // fprintf(f, "nr jited func lens: %u\n", bpf_info.nr_jited_func_lens);
      // printf("run count: %llu\n", bpf_info.run_cnt);
      // fprintf(f, "run count: %llu\n", bpf_info.run_cnt);
      // printf("run time ns: %llu\n", bpf_info.run_time_ns);
      // fprintf(f, "run time ns: %llu\n", bpf_info.run_time_ns);

      // printf("\n======END======\n");
      // fprintf(f, "\n======END======\n");

      fclose(f);
      free(fullPath);
      free(fullPath2);
      bpf_object__unload(bpf_obj);
      bpf_object__close(bpf_obj);
      munmap(mmapped_context_map_ptr, map_sz); //Noetig?
      
	return EXIT_SUCCESS;
}

// int read_write_with_uring(int fd, off_t interFilesOffset)
// {
// 	struct io_uring ring;
// 	struct io_uring_sqe* sqe;
// 	struct io_uring_cqe** cqes;
// 	struct iovec rw_iovec;
// 	void* buf;
// 	// int ENTRIES = 2;
// 	//void* buf2;
	
// 	int fdArray[2];
// 	off_t nr_of_bytes;
// 	int ret;
// 	off_t file_sz = get_file_size(fd);
// 	off_t bytes_remaining = file_sz;
// 	off_t writeOffset;
// 	off_t readOffset;
// 	off_t processed_blocks = 0;
// 	off_t total_nr_blocks = file_sz / (off_t) BLOCK_SZ;
// 	off_t nr_of_blocks_current_batch = 0;
// 	off_t blocks_remaining;
// 	//int temp;
// 	//int fd2;
	
// 	bool first = true;
	
// 	writeOffset = interFilesOffset;
// 	readOffset = 0;

// 	//Zus�tzlichen Block f�r Rest
// 	if (file_sz % (off_t) BLOCK_SZ) total_nr_blocks++;
	
// 	if ((buf = malloc(BLOCK_SZ)) == NULL )
// 	{
// 		perror("Error on malloc for read/write buffer");
// 		return 1;
// 	}
// 	blocks_remaining = total_nr_blocks;

// 	//Einfach in Schleife reusen, nicht jedes mal neu initialisieren
// 	//"As soon as an sqe is consumed by the kernel, the application is free to reuse that sqe entry."
// 	ret = io_uring_queue_init(ENTRIES, &ring, 0);
// 	if (ret != 0)
// 	{
// 		perror("Error on io_uring_queue_init");
// 		return 1;
// 	}
	

// 	cqes = malloc(ENTRIES * sizeof(struct io_uring_cqe*));

// 	while (blocks_remaining)
// 	{
// 		nr_of_blocks_current_batch = blocks_remaining;
// 		if (nr_of_blocks_current_batch > ENTRIES / 2) nr_of_blocks_current_batch = ENTRIES / 2;

// 		processed_blocks = 0;

// 		while (processed_blocks < nr_of_blocks_current_batch)
// 		{
// 			nr_of_bytes = bytes_remaining;
// 			if (nr_of_bytes > BLOCK_SZ) nr_of_bytes = BLOCK_SZ;

// 			sqe = io_uring_get_sqe(&ring);
// 			io_uring_prep_read(sqe, fd, buf, nr_of_bytes, readOffset);
// 			io_uring_sqe_set_flags(sqe, IOSQE_IO_DRAIN);

// 			sqe = io_uring_get_sqe(&ring);
// 			io_uring_prep_write(sqe, STDOUT_FILENO, buf, nr_of_bytes, writeOffset);
// 			io_uring_sqe_set_flags(sqe, IOSQE_IO_DRAIN);

// 			writeOffset += nr_of_bytes;
// 			readOffset += nr_of_bytes;

// 			processed_blocks++;
// 			bytes_remaining -= nr_of_bytes;
// 		}

// 		ret = io_uring_submit_and_wait(&ring, nr_of_blocks_current_batch * 2);
// 		if (ret != nr_of_blocks_current_batch * 2)
// 		{		
// 			//sollte hier eigtl. nie hinkommen
// 			perror("io_uring_submit_and_wait did not wait for the number of entries submitted");
// 			return 1;
// 		}

// 		//Hole alle cqes
// 		ret = io_uring_peek_batch_cqe(&ring, cqes, nr_of_blocks_current_batch * 2);
// 		if (ret != nr_of_blocks_current_batch * 2)
// 		{
// 			//Sollte hier eigtl. nie hinkommen
// 			perror("io_uring_peek_batch_cqe did not return the same number of cqes as entries were submitted");
// 			return 1;
// 		}

// 		//markiere alle cqes als gesehen
// 		for (int i = 0; i < ret; i++)
// 		{
// 			//Vllt in user data mitgeben ob es read oder write war und hier mit ausgeben..
// 			if (cqes[i]->res < 0)
// 			{
// 				perror("read/write syscall mit r�ckgabewert < 0");
// 				return 1;
// 			}

// 			io_uring_cqe_seen(&ring, cqes[i]);
// 		}

// 		blocks_remaining -= nr_of_blocks_current_batch;
// 	}

// 	io_uring_queue_exit(&ring);
// 	free(cqes);

// 	return 0;
// }

