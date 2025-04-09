#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#include <devices/shutdown.h>

#include <string.h>
#include <filesys/file.h>
#include <devices/input.h>
#include <threads/malloc.h>
#include <threads/palloc.h>
#include "process.h"
#include "pagedir.h"
#include <threads/vaddr.h>
#include <filesys/filesys.h>

#define MAX_SYSCALL 20

// lab01 Hint - Here are the system calls you need to implement.

/* System call for process. */

void sys_halt(struct intr_frame* f);
void sys_exit(struct intr_frame* f);
void sys_exec(struct intr_frame* f);
void sys_wait(struct intr_frame* f);

/* System call for file. */
void sys_create(struct intr_frame* f);
void sys_remove(struct intr_frame* f);
void sys_open(struct intr_frame* f);
void sys_filesize(struct intr_frame* f);
void sys_read(struct intr_frame* f);
void sys_write(struct intr_frame* f);
void sys_seek(struct intr_frame* f);
void sys_tell(struct intr_frame* f);
void sys_close(struct intr_frame* f);


static void (*syscalls[MAX_SYSCALL])(struct intr_frame *) = {
  [SYS_HALT] = sys_halt,
  [SYS_EXIT] = sys_exit,
  // [SYS_EXEC] = sys_exec,
  // [SYS_WAIT] = sys_wait,
  // [SYS_CREATE] = sys_create,
  // [SYS_REMOVE] = sys_remove,
  // [SYS_OPEN] = sys_open,
  // [SYS_FILESIZE] = sys_filesize,
  // [SYS_READ] = sys_read,
  [SYS_WRITE] = sys_write,
  // [SYS_SEEK] = sys_seek,
  // [SYS_TELL] = sys_tell,
  // [SYS_CLOSE] = sys_close
};

static void syscall_handler (struct intr_frame *);

void syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}


/* System Call: void halt (void)
    Terminates Pintos by calling shutdown_power_off() (declared in devices/shutdown.h). 
*/
void sys_halt(struct intr_frame * f UNUSED)
{
  shutdown_power_off();
}

void sys_exit(struct intr_frame* f)
{
	int exit_status = *(int *)(f->esp + 4);
	char *process_name = thread_current()->name;
	printf("%s: exit(%d)\n", process_name, exit_status);
	// printf("exit\n");
	thread_exit();
}

// write (int fd, const void *buffer, unsigned size)
void sys_write(struct intr_frame* f){
	int fd = *(int *)(f->esp + 4);
	const void *buffer = *(const void**)(f->esp + 8);
	uint32_t size = *(uint32_t *)(f->esp + 12);

	int bytes_written = 0;
	if(fd == 1) {
		putbuf(buffer, size);
		bytes_written = size;
	} else {
		printf("I'm not dealing with fd != 1\n");
	}
	f->eax = bytes_written; 
}

static void syscall_handler (struct intr_frame *f) 
{

	uint32_t syscall_num = *((uint32_t *)f->esp);
  // printf ("system call number %d\n", syscall_num);

	if(syscall_num < MAX_SYSCALL && syscalls[syscall_num] != NULL) {
		syscalls[syscall_num](f);
	} else {
		printf("Unknown system call:%u\n", syscall_num);
	}
  // thread_exit();
}
