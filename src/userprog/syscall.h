#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "user/syscall.h"
#include "threads/thread.h"
#include "threads/interrupt.h"
#include "threads/synch.h"
#include "userprog/process.h"


struct process_file
  {
    struct file *file;
    int fd;
    struct list_elem elem;
    struct dir* dir;
  };


/*syscall helper function*/
static void syscall_handler (struct intr_frame *);
int check_addr(void *);
void syscall_init (void);
// static bool is_uaddr_valid (void *uaddr);
void halt_sys();
void exit_sys(struct intr_frame *);
void exec_sys(struct intr_frame *);
void wait_sys(struct intr_frame *);
void create_sys(struct intr_frame *);
void remove_sys(struct intr_frame *);
void open_sys(struct intr_frame *);
void filesize_sys(struct intr_frame *);
void read_sys(struct intr_frame *);
void write_sys(struct intr_frame *);
void seek_sys(struct intr_frame *);
void tell_sys(struct intr_frame *);
void close_sys(struct intr_frame *);
void chdir_sys (struct intr_frame *f );
void mkdir_sys (struct intr_frame *f);
void readdir_sys (struct intr_frame *f);
void isdir_sys (struct intr_frame *f);
void inumber_sys (struct intr_frame *f);
  
#endif /* userprog/syscall. */
