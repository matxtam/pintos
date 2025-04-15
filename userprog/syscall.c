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

// System call declarations
void sys_halt(struct intr_frame *f);
void sys_exit(struct intr_frame* f);
void sys_exec(struct intr_frame* f);
void sys_wait(struct intr_frame* f);
void sys_create(struct intr_frame* f);
void sys_remove(struct intr_frame* f);
void sys_open(struct intr_frame* f);
void sys_filesize(struct intr_frame* f);
void sys_read(struct intr_frame* f);
void sys_write(struct intr_frame* f);
void sys_seek(struct intr_frame* f);
void sys_tell(struct intr_frame* f);
void sys_close(struct intr_frame* f);
void terminate_with_status(int status);
int allocate_fd(struct file *file);


// Helper function to handle fatal errors with exit(-1)
void terminate_with_status(int status) {
  printf("%s: exit(%d)\n", thread_name(), status);
  thread_exit();
}
static int get_user (const uint8_t *uaddr) {
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}
static void check_ptr2(const void *vaddr) {
  if (!is_user_vaddr(vaddr)) terminate_with_status(-1);
  void *ptr = pagedir_get_page(thread_current()->pagedir, vaddr);
  if (!ptr) terminate_with_status(-1);
  const uint8_t *check_byteptr = (const uint8_t *)vaddr;
  for (int i = 0; i < 4; ++i) {
    if (get_user(check_byteptr + i) == -1)
      terminate_with_status(-1);
  }
}
// Helper functions for checking user memory
void check_address(const void *addr) {
  if (addr == NULL || !is_user_vaddr(addr)) terminate_with_status(-1);

  void *page = pagedir_get_page(thread_current()->pagedir, addr);
  if (page == NULL) {
    terminate_with_status(-1);
  }
}


static void check_string(const char *str) {
  for (int i = 0; i < 4096; ++i) { // 最多查一整頁，避免無窮 loop
    check_address(str + i);  // 檢查每個位址合法
    if (str[i] == '\0') return;
  }
  terminate_with_status(-1); // 超過最大長度還沒結束字串
}


static void check_buffer(void *buffer, unsigned size) {
  uint8_t *start = (uint8_t *)buffer;
  uint8_t *end = start + size;

  for (uint8_t *ptr = start; ptr < end; ptr++) {
    check_address(ptr);
  }

}

static void (*syscalls[MAX_SYSCALL])(struct intr_frame *) = {
  [SYS_HALT] = sys_halt,
  [SYS_EXIT] = sys_exit,
  [SYS_EXEC] = sys_exec,
  [SYS_WAIT] = sys_wait,
  [SYS_CREATE] = sys_create,
  [SYS_REMOVE] = sys_remove,
  [SYS_OPEN] = sys_open,
  [SYS_FILESIZE] = sys_filesize,
  [SYS_READ] = sys_read,
  [SYS_WRITE] = sys_write,
  [SYS_SEEK] = sys_seek,
  [SYS_TELL] = sys_tell,
  [SYS_CLOSE] = sys_close
};

static void syscall_handler (struct intr_frame *f) {
  check_address(f->esp);
  check_address((int *)f->esp);  // Also ensure we can safely dereference syscall number
  int *p = f->esp;
  check_ptr2(p + 1);  // 確保 syscall number 是有效 user 指標

  int syscall_number = *(int*)(f->esp);
  if (syscall_number >= 0 && syscall_number < MAX_SYSCALL && syscalls[syscall_number]) {
    syscalls[syscall_number](f);
  } else {
    printf("Unknown syscall number: %d\n", syscall_number);
    terminate_with_status(-1);
  }
}

void syscall_init (void) {
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void sys_halt(struct intr_frame *f) {
  (void)f;
  shutdown_power_off();
}

void sys_exit(struct intr_frame *f) {
  check_address(f->esp + 4);
  int status = *(int*)(f->esp + 4);
  
  struct thread *cur = thread_current();
  cur->exit_status = status;  // 存起來讓 wait() 可以拿

  printf("%s: exit(%d)\n", thread_name(), status);
  thread_exit();  // 結束目前 thread
}


void sys_write(struct intr_frame *f) {
  check_address(f->esp + 4);  // fd
  check_address(f->esp + 8);  // buffer
  check_address(f->esp + 12); // size
  

  int fd = *(int *)(f->esp + 4);
  const char *buffer = *(const char **)(f->esp + 8);
  unsigned size = *(unsigned *)(f->esp + 12);
  
  check_buffer((void *)buffer, size);

  if (fd == 1) {
    putbuf(buffer, size);
    f->eax = size;
  } else if (fd >= 2 && fd < MAX_FD) {
    struct file *file = thread_current()->fd_table[fd];
    if (file == NULL) {
      terminate_with_status(-1);
      //f->eax = -1;
    } else {
			// printf("[DEBUG] syswrite to file");
			filesys_lock_acquire ();
      f->eax = file_write(file, buffer, size);
			filesys_lock_release ();
    }
  } else {
    f->eax = -1;
  }
}


void sys_exec(struct intr_frame *f) {
  void *arg_ptr;

  // 第一步：檢查 f->esp + 4 本身是否合法
  check_address(f->esp + 4);                           

  // 第二步：解出 user 傳來的指標（要再檢查這個指標本身）
  arg_ptr = *(void **)(f->esp + 4);                    

  // 第三步：檢查這個指標指向的記憶體區段是否合法
  check_address(arg_ptr);                             
  check_string((char *)arg_ptr);                      

  // 最後呼叫執行
  f->eax = process_execute((char *)arg_ptr);
}


void sys_wait(struct intr_frame* f) {
  check_address(f->esp + 4);
  tid_t pid = *(tid_t *)(f->esp + 4);
  f->eax = process_wait(pid);
}

void sys_read(struct intr_frame *f) {

  check_address(f->esp + 4);  // fd
  check_address(f->esp + 8);  // buffer
  check_address(f->esp + 12); // size
    
  
  
  int fd = *(int *)(f->esp + 4);
  void *buffer = *(void **)(f->esp + 8);
  unsigned size = *(unsigned *)(f->esp + 12);

  check_buffer(buffer, size);

  if (fd == 0) {
    uint8_t *buf = (uint8_t *)buffer;
    for (unsigned i = 0; i < size; i++) {
      buf[i] = input_getc();
    }
    f->eax = size;
  } else if (fd >= 2 && fd < MAX_FD) {
    struct file *file = thread_current()->fd_table[fd];
    if (file == NULL) {
      terminate_with_status(-1);
      //f->eax = -1;
    } else {
      f->eax = file_read(file, buffer, size);
    }
  } else {
    f->eax = -1;
  }
}


void sys_create(struct intr_frame* f) {
  check_address(f->esp + 4);                             // 檢查參數指標是否有效
  const char *file_ptr = *(char **)(f->esp + 4);         // 取得 user 傳進來的檔名指標
  check_address(file_ptr);                               // 再檢查那個指標本身
  check_string(file_ptr);                                // 檢查檔名指標是否有效（結尾 '\0'）

  check_address(f->esp + 8);                             // 檢查 size 的位置也別忘了

  unsigned initial_size = *(unsigned *)(f->esp + 8);

	filesys_lock_acquire();
  f->eax = filesys_create(file_ptr, initial_size);
  /*if (f->eax) {
    struct file *temp = filesys_open(file_ptr);
    if (temp != NULL) {
      file_close(temp);
    }
  }*/
	filesys_lock_release();
	// printf("file created\n");
}


void sys_remove(struct intr_frame* f) {
  check_address(f->esp + 4);
  const char *file = *(char **)(f->esp + 4);
  check_string(file);
  f->eax = filesys_remove(file);
}

int allocate_fd(struct file *file) {
  struct thread *t = thread_current();
  for (int fd = 2; fd < MAX_FD; fd++) {
    if (t->fd_table[fd] == NULL) {
      t->fd_table[fd] = file;
      return fd;
    }
  }
  return -1;
}

void sys_open(struct intr_frame *f) {
  check_address(f->esp + 4);  // fd
  check_address(f->esp + 8);  // buffer
  check_address(f->esp + 12); // size
  
  const char *filename = *(const char **)(f->esp + 4);
  check_string(filename);

  struct file *file = filesys_open(filename);
  if (file == NULL) {
    f->eax = -1;
    return;
  }

  int fd = allocate_fd(file);
  if (fd == -1) {
    file_close(file);
    f->eax = -1;  
    return;
  }

  f->eax = fd;
}


void sys_close(struct intr_frame *f) {
  check_address(f->esp + 4);  // fd
  check_address(f->esp + 8);  // buffer
  check_address(f->esp + 12); // size
  
  int fd = *(int *)(f->esp + 4);

  if (fd < 2 || fd >= MAX_FD) {
    return;
  }

  struct thread *t = thread_current();
  struct file *file = t->fd_table[fd];
  if (file != NULL) {
    file_close(file);
    t->fd_table[fd] = NULL;
  }
}


void sys_filesize(struct intr_frame *f) {
  check_address(f->esp + 4);  // fd
  check_address(f->esp + 8);  // buffer
  check_address(f->esp + 12); // size
  
  int fd = *(int *)(f->esp + 4);

  struct file *file = thread_current()->fd_table[fd];
  if (file == NULL) {
    f->eax = -1;
    return;
  }
  f->eax = file_length(file);
}

void sys_seek(struct intr_frame *f) {
  check_address(f->esp + 4);  // fd
  check_address(f->esp + 8);  // buffer
  check_address(f->esp + 12); // size
  
  int fd = *(int *)(f->esp + 4);
  unsigned position = *(unsigned *)(f->esp + 8);

  struct file *file = thread_current()->fd_table[fd];
  if (file != NULL) {
    file_seek(file, position);
  }
}

void sys_tell(struct intr_frame *f) {
  check_address(f->esp + 4);  // fd
  check_address(f->esp + 8);  // buffer
  check_address(f->esp + 12); // size
  
  int fd = *(int *)(f->esp + 4);

  struct file *file = thread_current()->fd_table[fd];
  if (file == NULL) {
    f->eax = -1;
    return;
  }
  f->eax = file_tell(file);
}
