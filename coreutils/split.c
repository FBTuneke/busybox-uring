/* vi: set sw=4 ts=4: */
/*
 * split - split a file into pieces
 * Copyright (c) 2007 Bernhard Reutner-Fischer
 *
 * Licensed under GPLv2 or later, see file LICENSE in this source tree.
 */
//config:config SPLIT
//config:	bool "split (5 kb)"
//config:	default y
//config:	help
//config:	Split a file into pieces.
//config:
//config:config FEATURE_SPLIT_FANCY
//config:	bool "Fancy extensions"
//config:	default y
//config:	depends on SPLIT
//config:	help
//config:	Add support for features not required by SUSv3.
//config:	Supports additional suffixes 'b' for 512 bytes,
//config:	'g' for 1GiB for the -b option.

//applet:IF_SPLIT(APPLET(split, BB_DIR_USR_BIN, BB_SUID_DROP))

//kbuild:lib-$(CONFIG_SPLIT) += split.o

/* BB_AUDIT: SUSv3 compliant
 * SUSv3 requirements:
 * http://www.opengroup.org/onlinepubs/009695399/utilities/split.html
 */

//usage:#define split_trivial_usage
//usage:       "[OPTIONS] [INPUT [PREFIX]]"
//usage:#define split_full_usage "\n\n"
//usage:       "	-b N[k|m]	Split by N (kilo|mega)bytes"
//usage:     "\n	-l N		Split by N lines"
//usage:     "\n	-a N		Use N letters as suffix"
//usage:
//usage:#define split_example_usage
//usage:       "$ split TODO foo\n"
//usage:       "$ cat TODO | split -a 2 -l 2 TODO_\n"


#include "../include/common_bufsiz.h"
#include "../include/common.h"

#include "liburing.h" //Wichtig - dieses io_uring  nehmen - vor split_common.h. TODO: Mal aufräumen
#include "../include/split_common.h"
#include "../../linux/tools/lib/bpf/libbpf.h"
#include "../../linux/tools/lib/bpf/bpf.h"

#include <time.h>
#include <math.h>

#define NR_OF_BPF_PROGS 1


#if ENABLE_FEATURE_SPLIT_FANCY
static const struct suffix_mult split_suffixes[] = {
	{ "b", 512 },
	{ "k", 1024 },
	{ "m", 1024*1024 },
	{ "g", 1024*1024*1024 },
	{ "", 0 }
};
#endif

/* Increment the suffix part of the filename.
 * Returns NULL if we are out of filenames.
 */
// static char *next_file(char *old, unsigned suffix_len)
// {
// 	size_t end = strlen(old);
// 	unsigned i = 1;
// 	char *curr;

// 	while (1) {
// 		curr = old + end - i;
// 		if (*curr < 'z') {
// 			*curr += 1;
// 			break;
// 		}
// 		i++;
// 		if (i > suffix_len) {
// 			return NULL;
// 		}
// 		*curr = 'a';
// 	}

// 	return old;
// }

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

#ifndef __NR_io_uring_register
      #define __NR_io_uring_register 427
#endif

int __sys_io_uring_register(int fd, unsigned opcode, const void *arg, unsigned nr_args)
{
	return syscall(__NR_io_uring_register, fd, opcode, arg, nr_args);
}

#define SPLIT_OPT_l (1<<0)
#define SPLIT_OPT_b (1<<1)
#define SPLIT_OPT_a (1<<2)

int split_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int split_main(int argc UNUSED_PARAM, char **argv)
{
	unsigned suffix_len = 2;
	char *pfx;
	char *count_p;
	const char *sfx;
	off_t cnt = 1000;
	// off_t remaining = 0;
	unsigned opt;
	// ssize_t bytes_read, to_write;
	// char *src;

	struct io_uring ring;
	struct io_uring_sqe* sqe;
	// struct io_uring_cqe** cqes;
	struct io_uring_cqe* cqe;
	int ret;
	// int fd = 0;
	// int oldFd = 1;
	// int offsetWrite = 0;
	// int offsetRead = 0;
	// int nrOfEntries = 0;
	// bool firstLoop = true;
	// int nrOfOpenFiles = 0;
	// int nrOfOpenedFiles = 0;
	// int nrOfCloses = 0;
	// int nrOfCurrentEntries = 0;
	// char* read_buffer;
      int *fixed_fds;
      int nr_of_output_files;

	// read_buffer = malloc(READ_BUFFER_SIZE * sizeof(char));

	setup_common_bufsiz();

	opt = getopt32(argv, "^"
			"l:b:a:+" /* -a N */
			"\0" "?2"/*max 2 args*/,
			&count_p, &count_p, &suffix_len
	);

	if (opt & SPLIT_OPT_l)
		cnt = XATOOFF(count_p);
	if (opt & SPLIT_OPT_b) // FIXME: also needs XATOOFF
		cnt = xatoull_sfx(count_p,
				IF_FEATURE_SPLIT_FANCY(split_suffixes)
				IF_NOT_FEATURE_SPLIT_FANCY(km_suffixes)
		);
	sfx = "x";

	argv += optind;
	if (argv[0]) 
	{
		int fd;
		if (argv[1])
			sfx = argv[1];
		fd = xopen_stdin(argv[0]);
		xmove_fd(fd, STDIN_FILENO);
	} else {
		argv[0] = (char *) bb_msg_standard_input;
	}

	if (NAME_MAX < strlen(sfx) + suffix_len)
		bb_error_msg_and_die("suffix too long");

	{
		char *char_p = xzalloc(suffix_len + 1);
		memset(char_p, 'a', suffix_len);
		pfx = xasprintf("%s%s", sfx, char_p);
		if (ENABLE_FEATURE_CLEAN_UP)
			free(char_p);
	}

      struct io_uring_params params;
      uint32_t cq_sizes[4] = {128, 128, 128, 128};
      struct bpf_object *bpf_obj;
      struct bpf_program *bpf_prog;
      const char *name_object_file, *name;
      uint32_t kversion;
      int prog_fds[NR_OF_BPF_PROGS];
      size_t map_sz;
      void *mmapped_context_map_ptr;
      ebpf_context_t *context_ptr;
      int context_map_fd;
      char buf_path[PATH_MAX];

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

      libbpf_set_print(libbpf_print); //setze libbpf error und debug callback
      bump_memlock_rlimit();

      struct timeval begin, end;
      gettimeofday(&begin, 0);

      exe_path(buf_path);
      // printf("before path: %s\n", buf_path);
      strcat(buf_path, "/split_ebpf.o");


      bpf_obj = bpf_object__open(buf_path);
      // bpf_obj = bpf_object__open("split_ebpf.o");

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
      printf("name_object_file: %s\n", name_object_file);

      kversion = bpf_object__kversion(bpf_obj);
      printf("kversion: %i\n", kversion);

      for(int i = 0; i < NR_OF_BPF_PROGS; i++)
      {
            if(i == 0) bpf_prog = bpf_program__next(NULL, bpf_obj);
            else bpf_prog = bpf_program__next(bpf_prog, bpf_obj);

            name = bpf_program__name(bpf_prog);
            printf("program %i name: %s\n", i, name);
            name = bpf_program__section_name(bpf_prog);
            printf("program %i section name: %s\n", i, name);          
            // int_temp = bpf_program__size(bpf_prog);
            // printf("program size: %i\n", int_temp);

            prog_fds[i] = bpf_program__fd(bpf_prog);
            printf("bpf-program %i fd: %i\n", i, prog_fds[i]);
      } 

      context_map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "context_map");
      printf("context map fd: %i\n", context_map_fd);
   
      map_sz = roundup_page(1 * sizeof(ebpf_context_t));
      mmapped_context_map_ptr = mmap(NULL, map_sz, PROT_READ | PROT_WRITE, MAP_SHARED, context_map_fd, 0);
      if (mmapped_context_map_ptr == MAP_FAILED || !mmapped_context_map_ptr)
      {
            printf("mmap context map error \n");
            return -1;
      }
      context_ptr = (ebpf_context_t*) mmapped_context_map_ptr;

      context_ptr->suffix_len = suffix_len;
      context_ptr->pfx_len = strlen(sfx) + suffix_len;
      context_ptr->cnt = cnt;
      context_ptr->read_buffer_userspace_base_ptr = context_ptr->read_buffer;
      context_ptr->pfx_buffer_userspace_base_ptr = context_ptr->pfx_buffer;
      context_ptr->fixed_fd = 1;
      memcpy(context_ptr->pfx_buffer, pfx, context_ptr->pfx_len + 1);

#ifdef IO_URING_FIXED_FILE
      nr_of_output_files = 1000; //Max 1024 fds gleichzeitig offen
      fixed_fds = (int*) malloc((nr_of_output_files + 1) * sizeof(int));
      fixed_fds[0] = STDIN_FILENO;

      for(int i = 1; i < nr_of_output_files + 1; i++)
            fixed_fds[i] = -1;

      ret = io_uring_register_files(&ring, fixed_fds, nr_of_output_files);
      if (ret < 0) 
      {
            printf("reg failed %d\n", ret);
            exit(1);
      }
#endif

      ret = __sys_io_uring_register(ring.ring_fd, IORING_REGISTER_BPF, prog_fds, NR_OF_BPF_PROGS);
      if(ret < 0)
      {
            printf("Error __sys_io_uring_register, ret: %i\n", ret);
            return -1;
      }

//------Zeitmessung start      
      // clock_t begin = clock();
      gettimeofday(&begin, 0);

      sqe = io_uring_get_sqe(&ring);
      if (!sqe)
      {
            printf("get sqe #1 failed\n");
            return -1;
      }
      
#ifdef IO_URING_FIXED_FILE
      io_uring_prep_read(sqe, STDIN_FILENO_FIX, context_ptr->read_buffer, READ_BUFFER_SIZE, 0);
      sqe->user_data = 99;
      sqe->flags = IOSQE_IO_HARDLINK | IOSQE_FIXED_FILE;
      sqe->cq_idx = READ_CQ_IDX;
#else
      io_uring_prep_read(sqe, STDIN_FILENO, context_ptr->read_buffer, READ_BUFFER_SIZE, 0);
      sqe->user_data = 99;
      sqe->flags = IOSQE_IO_HARDLINK;
      sqe->cq_idx = READ_CQ_IDX;
#endif

      sqe = io_uring_get_sqe(&ring);
      if (!sqe)
      {
            printf("get sqe #2 failed\n");
            return -1;
      }

#ifdef IO_URING_FIXED_FILE
      io_uring_prep_openat_direct(sqe, AT_FDCWD, pfx, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH, context_ptr->fixed_fd);
#else
      io_uring_prep_openat(sqe, AT_FDCWD, pfx, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
#endif
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
	sqe->off = SPLIT_PROG; //Scheint der Index des eBPF-Programms zu sein.
	sqe->opcode = IORING_OP_BPF;
	sqe->flags = 0;
      sqe->cq_idx = SINK_CQ_IDX;

      ret = io_uring_submit(&ring);
	if (ret <= 0) 
      {
		printf("sqe submit failed: %i\n", ret);
		return -1;
	}


      printf("\n======START======\n");
      while(1)
      {
            ret = io_uring_wait_cqe(&ring, &cqe);
            io_uring_cqe_seen(&ring, cqe);
            
            printf("\ncqe->user_data: %llu\n", cqe->user_data);
            printf("cqe->res: %i\n", cqe->res);

            if(cqe->user_data == SPLIT_COMPLETE)
            {
                  break;
            }
            else if(cqe->user_data == SUFFIX_EXHAUSTED)
            {
                  printf("SUFFIX EXHAUSTED!\n");
                  return EXIT_FAILURE;
            }
      }

      gettimeofday(&end, 0);
      seconds = end.tv_sec - begin.tv_sec;
      microseconds = end.tv_usec - begin.tv_usec;
      double time_spent_split = seconds + microseconds*1e-6;

      struct bpf_prog_info bpf_info = {};
      uint32_t info_len = sizeof(bpf_info);

      ret = bpf_obj_get_info_by_fd(prog_fds[0], &bpf_info, &info_len);
	if(ret != 0)
            printf("Error bpf_obj_get_info_by_fd(): %i\n", ret);
      
      char *fullPath;
      char *fileName = "/split-bpf-log.txt";
      fullPath = malloc(strlen(getenv("HOME") + strlen(fileName)) + 1); // to account for NULL terminator
      strcpy(fullPath, getenv("HOME"));
      strcat(fullPath, fileName);

      FILE *f;
      f = fopen(fullPath, "a");

      // clock_t end = clock();
      // double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
      printf("Verbrauchte Zeit fuer das Laden und Oeffnen des BPF-Programms: %.3f in Sekunden\n", time_spent_loading_bpf_prog);
      fprintf(f, "Verbrauchte Zeit fuer das Laden und Oeffnen des BPF-Programms: %.3f in Sekunden\n", time_spent_loading_bpf_prog);      
      printf("Verbrauchte Zeit fuer das eigentliche Splitting: %.3f in Sekunden\n", time_spent_split);
      fprintf(f, "Verbrauchte Zeit für das eigentliche Splitting: %.3f in Sekunden\n", time_spent_split);
      printf("Jited prog instructions: %llu\n", bpf_info.jited_prog_insns);
      fprintf(f, "Jited prog instructions: %llu\n", bpf_info.jited_prog_insns);
      printf("Jited prog length: %u\n", bpf_info.jited_prog_len);
      fprintf(f, "Jited prog length: %u\n", bpf_info.jited_prog_len);
      printf("load time (ns since boottime): %llu\n", bpf_info.load_time);
      fprintf(f, "load time (ns since boottime): %llu\n", bpf_info.load_time);
      printf("nr func info: %u\n", bpf_info.nr_func_info);
      fprintf(f, "nr func info: %u\n", bpf_info.nr_func_info);
      printf("nr jited func lens: %u\n", bpf_info.nr_jited_func_lens);
      fprintf(f, "nr jited func lens: %u\n", bpf_info.nr_jited_func_lens);
      printf("run count: %llu\n", bpf_info.run_cnt);
      fprintf(f, "run count: %llu\n", bpf_info.run_cnt);
      printf("run time ns: %llu\n", bpf_info.run_time_ns);
      fprintf(f, "run time ns: %llu\n", bpf_info.run_time_ns);

      printf("\n======END======\n");
      fprintf(f, "\n======END======\n");

      fclose(f);

      return EXIT_SUCCESS;

	// bytes_read = safe_read(STDIN_FILENO, read_buffer, READ_BUFFER_SIZE);
	
	// if (!bytes_read)
	// {
	// 	perror("Did read zero bytes on first safe_read");
	// 	return 1;
	// }
	// if (bytes_read < 0) bb_simple_perror_msg_and_die(argv[0]);
	
	// src = read_buffer;

	// offsetRead += bytes_read;

	// while (1) 
	// {	
	// 	nrOfEntries = 0;
	// 	if(!remaining) firstLoop = true;
	// 	nrOfOpenFiles = 0;
	// 	nrOfCloses = 0;
		
	// 	do 
	// 	{
	// 		if (!remaining) 
	// 		{
	// 			if (!pfx) bb_error_msg_and_die("suffixes exhausted");
	// 			//xmove_fd(xopen(pfx, O_WRONLY | O_CREAT | O_TRUNC), 1);

	// 			fd = xopen(pfx, O_WRONLY | O_CREAT | O_TRUNC);
	// 			nrOfOpenFiles++;
	// 			nrOfOpenedFiles++;
				
	// 			// printf("Filedeskriptor: %i\n", fd);
				
	// 			if (firstLoop)
	// 			{
	// 				firstLoop = false;
	// 				oldFd = fd;
	// 			}

	// 			pfx = next_file(pfx, suffix_len);
	// 			remaining = cnt;
	// 			offsetWrite = 0;
	// 		}

	// 		if (opt & SPLIT_OPT_b) 
	// 		{
	// 			/* split by bytes */
	// 			to_write = (bytes_read < remaining) ? bytes_read : remaining;
	// 			remaining -= to_write;
	// 		} 
	// 		else 
	// 		{
	// 			/* split by lines */
	// 			/* can be sped up by using _memrchr_
	// 			 * and writing many lines at once... */
	// 			char *end = memchr(src, '\n', bytes_read);
	// 			if (end) 
	// 			{
	// 				--remaining;
	// 				to_write = end - src + 1;
	// 			} 
	// 			else to_write = bytes_read;
	// 		}

	// 		//File kann geschlossen werden, wenn neues ge�ffnet
	// 		if (oldFd != fd)
	// 		{
	// 			sqe = io_uring_get_sqe(&ring);
	// 			io_uring_prep_close(sqe, oldFd);
	// 			io_uring_sqe_set_flags(sqe, IOSQE_IO_DRAIN);
				
	// 			// close(oldFd); //geht nat�rlich nicht, geht erst nach dem gelesen/geschrieben wurde..
	// 			// printf("closed file\n");
	// 			nrOfCloses++;
	// 			oldFd = fd;
	// 			nrOfEntries++;
	// 		}
		
	// 		//Man k�nnte verschiedene Ketten machen, die parallel ablaufen. f�r jede Datei eine eigene KEtte. Wei� aber nicht ob das hier viel bringt, der buffer oben ist nur 1024 byte gro�...
	// 		sqe = io_uring_get_sqe(&ring);
	// 		io_uring_prep_write(sqe, fd, src, to_write, offsetWrite);
	// 		io_uring_sqe_set_flags(sqe, IOSQE_IO_DRAIN);

	// 		//xwrite(STDOUT_FILENO, src, to_write);
	// 		bytes_read -= to_write;
	// 		src += to_write;
	// 		offsetWrite += to_write;
	// 		nrOfEntries++;

	// 	} while (bytes_read);
		
		
	// 	// Fall: Buffer zu Ende gelesen und Datei zu Ende geschrieben. Tritt dies auf, dann greift die obere Abfrage (olFd != fd) nicht, da fd erst in dem n�chsten
	// 	// Schleifendurchlauf ge�ndert werden w�rde, den es aber nicht mehr gibt. Also muss hier noch mal geclosed werden.
	// 	if(!remaining) 
	// 	{
	// 			// printf("---------Adding Close sqe fuer Fall 2---------");
	// 			sqe = io_uring_get_sqe(&ring);
	// 			io_uring_prep_close(sqe, fd);
	// 			io_uring_sqe_set_flags(sqe, IOSQE_IO_DRAIN);
	// 			nrOfCloses++;
	// 			nrOfEntries++;
	// 	}
		
	// 	// printf("Anzahl gleichzeitig offener Files: %i\n", nrOfOpenFiles);
	// 	// printf("Anzahl insgesamt geoeffnter Files: %i\n", nrOfOpenedFiles);
	// 	// printf("Anzahl von Close-SQES in uring: %i\n", nrOfCloses);
		
	// 	// printf("Anzahl an SQEs: %i\n", nrOfEntries);
		
	// 	//Hier m�sste man eigtl. abfragen ob offsetRead > Filegr��e ist. Wenn ja, keinen read mehr in uring einreihen
	// 	//Man k�nnte auch schauen ob bytes_read % READ_BUFFER_SIZE != 0 ist, das m�sste dann n�mlich der etzte "Rest" an Bytes der Datei sein, der gelesen wurde
	// 	//Scheint zu funktionieren, read-SQE scheint wohl, wenn der file-pointer durch den offset-Parameter auf eine Stelle au�erhalb des Files zeigen w�rde mit 0 zur�ckzukehren.

	// 	sqe = io_uring_get_sqe(&ring);
	// 	io_uring_prep_read(sqe, STDIN_FILENO, read_buffer, READ_BUFFER_SIZE, offsetRead);
	// 	io_uring_sqe_set_flags(sqe, IOSQE_IO_DRAIN);
	// 	nrOfEntries++;
		
		
	// 	//VERBRAUCHT DAS HIER SO VIEL ZEIT?! - denke eher nicht angeblich laut stackoverflow "unmeasurable difference"
	// 	cqes = malloc(nrOfEntries * sizeof(struct io_uring_cqe*));

	// 	ret = io_uring_submit_and_wait(&ring, nrOfEntries);
	// 	if (ret != nrOfEntries)
	// 	{
	// 		perror("io_uring_submit_and_wait did not wait for the number of entries submitted");
	// 		return 1;
	// 	}
	// 	//Hole alle cqes
	// 	ret = io_uring_peek_batch_cqe(&ring, cqes, nrOfEntries);
	// 	if (ret != nrOfEntries)
	// 	{
	// 		//Sollte hier eigtl. nie hinkommen
	// 		perror("io_uring_peek_batch_cqe did not return the same number of cqes as entries were submitted");
	// 		return 1;
	// 	}			

	// 	//markiere alle cqes als gesehen
	// 	for (int i = 0; i < ret-1; i++)
	// 	{
	// 		if (cqes[i]->res < 0)
	// 		{
	// 			perror("write/close syscall mit r�ckgabewert < 0");
	// 			printf("Error on syscall nummer %i\n", i);
	// 			return 1;
	// 		}

	// 		io_uring_cqe_seen(&ring, cqes[i]);
	// 	}

	// 	//Letzer CQE geh�rt zum read-SQE, da Serialisierung
	// 	//R�ckgabewert holen und f�r n�chsten Schleifendurchlauf vorbereiten, oder Error oder fertig (alles von Datei gelesen)
	// 	bytes_read = cqes[ret - 1]->res;
		
	// 	// printf("Bytes read: %i\n", bytes_read);
		
	// 	io_uring_cqe_seen(&ring, cqes[ret - 1]);

	// 	free(cqes);
		
	// 	//finished
	// 	if (!bytes_read) break;

	// 	if (bytes_read < 0)
	// 	{
	// 		perror("Error - bytes_read from read sqe < 0");
	// 		bb_simple_perror_msg_and_die(argv[0]);
	// 	}

	// 	src = read_buffer;
	// 	offsetRead += bytes_read;
	// }

	// io_uring_queue_exit(&ring);
	// // printf("Reabuffersize: %i\n", READ_BUFFER_SIZE);

	// return EXIT_SUCCESS;
}
