#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/shutdown.h"
#include "devices/input.h"
#include "devices/block.h"
#include "lib/kernel/list.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "filesys/free-map.h"

#define DEBUG 0

/* Address validation. */
/* Return 1 if valid, return 0 otherwise. */

bool
each_add_check(char*f){
    if ((const void*)f != NULL && is_user_vaddr((const void*)f) && pagedir_get_page(thread_current()->pagedir,(const void*)f)){
    return true;
  } else  {
    return false;
  }
}

int check_addr(void *f){
  int count  = 0;
  for (;count < 4; count ++){
    if(!each_add_check((char*)f + count)){
      return 0;
    }
  }
  return 1;
}


/* Checks the validity of the user str. Returns true if the string
   is valid i.e. in user virtual memory. */

static bool
valid_string (const void *str)
{
  if (check_addr (str) == 0)  return false; 
  else  return true;
}


void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f )
{
  int * p = f->esp;
  /* Address validation. */
  if (check_addr (p) == 0){
    thread_current ()->exit_code = -1;
    thread_exit ();
  }

  /* Match syscall according to the pointer. */
  int system_call = * p;
  switch (system_call){
    case SYS_HALT:
      halt_sys ();
      break;

    case SYS_EXIT:
      exit_sys (f);
      break;

	case SYS_EXEC:
      exec_sys (f);
      break;

	case SYS_WAIT:
      wait_sys (f);
	    break;

	case SYS_CREATE:
      create_sys (f);
      break;

    case SYS_REMOVE:
      remove_sys (f);
      break;

	case SYS_OPEN:
      open_sys (f);
      break;

	case SYS_FILESIZE:
      filesize_sys (f);
	    break;

	case SYS_READ:
      read_sys (f);
      break;

	case SYS_WRITE:
      write_sys (f);
      break;

	case SYS_SEEK:
      seek_sys (f);
      break;

	case SYS_TELL:
      tell_sys (f);
      break;

	case SYS_CLOSE:
      close_sys (f);
      break;

  case SYS_CHDIR:
      chdir_sys (f);
      break;

  case SYS_MKDIR:
      mkdir_sys (f);
      break;

  case SYS_READDIR:
      readdir_sys (f);
      break;

  case SYS_ISDIR:
      isdir_sys (f);
      break;

  case SYS_INUMBER:
      inumber_sys (f);
      break;

    default:
      thread_current ()->exit_code =-1;
      thread_exit ();
  }
}

/* Syscall functions*/

/* Terminates Pintos. */
void halt_sys (){
  shutdown_power_off ();
}

/* Terminates the current user program, returning status to the kernel. */
void exit_sys (struct intr_frame *f){
  int * p = f->esp;

  /* Invalid address. */
  /* Modify the exit_code to -1 and exit the thead. */
  if (check_addr (p+1) == 0){
    thread_current ()->exit_code = -1;
  } else {
      /* Nornal case. */
    thread_current ()->exit_code = *(p+1);
  }

  /* Modify the exit_code to argv[0] and then exit the thead. */
  // thread_exit (thread_current ()->exit_code);
  // thread_current ()->exit_code = -1 ;
  thread_exit();
}

/* Runs the executable. */
void exec_sys (struct intr_frame * f){
  int * p = f->esp;

  /* Invalid address. */
  /* Set the return value (eax) to -1. */
  /* Modify the exit_code to -1 and exit the thead. */
  if (check_addr(p+1) == 0 || (valid_string (*((char **) ((char *)f->esp + 4))) == false)){
    f->eax = -1;
    thread_current()->exit_code = -1;
    thread_exit ();
    return;
  }

  /* Nornal case. */
  /* Set the return value (eax) to the new process's pid. */
  f -> eax = process_execute ((char*)*(p+1));
}

/* Wait for a child process pid and retrieve the child's exit status. */
void wait_sys (struct intr_frame *f){
  int * p = f->esp;

  /* Invalid address. */
  /* Set the return value (eax) to -1. */
  /* Modify the exit_code to -1 and exit the thead. */
  if (check_addr (p+1) == 0 ){
    f->eax = -1;
    thread_current ()->exit_code = -1;
    thread_exit ();
    return;
  }

  /* Normal case.*/
  f -> eax = process_wait (*(p+1));
}

/* Creates a new file. */
void create_sys (struct intr_frame *f){
  int * p = f->esp;

  /* Invalid address. */
  /* Set the return value (eax) to false. */
  /* Modify the exit_code to -1 and exit the thead. */
  if (check_addr (p+1) == 0 || check_addr (p+2) == 0 || (valid_string (*((char **) ((char *)f->esp + 4))) == false)){
    f-> eax = false;
    thread_current ()->exit_code = -1;
    thread_exit ();

    return;
  }
  /* Normal case. Create the file. */
  /* Use lock to assure the synchronozation. */
  // acquire_lock ();

  f -> eax = filesys_create (*((char **) ((char *)f->esp + 4)), *((unsigned *)f->esp + 2));
  // release_lock ();

}

/*Deletes the file. */
void remove_sys (struct intr_frame *f) {
  int *p = f->esp;

  /* Invalid address. */
  /* Set the return value (eax) to false. */
  /* Modify the exit_code to -1 and exit the thead. */
  if (check_addr (p + 1) == 0 || (valid_string (*((char **) ((char *)f->esp + 4))) == false)) {
    f->eax = false;
    thread_current ()->exit_code = -1;
    thread_exit ();
    return;
  }

  /* Normal case. Romove the file.*/
  /* Use lock to assure the synchronozation. */
  // acquire_lock ();
  f->eax = filesys_remove ((const char*)*(p + 1));
  // release_lock ();
}

/* Opens the file.*/
void open_sys(struct intr_frame *f){
  int * p = f->esp;
  /* Invalid address. */
  /* Set the return value (eax) to -1. */
  /* Modify the exit_code to -1 and exit the thead. */
  if (check_addr (p+1) == 0 || (valid_string (*((char **) ((char *)f->esp + 4))) == false)){
    f->eax = -1;
    thread_current ()->exit_code = -1;
    thread_exit ();
    return;
  }

  /* Try to open the file. */
  /* Use lock to assure the synchronozation. */
  // acquire_lock ();
  struct file * open_file = filesys_open ((const char*)*(p+1));
  struct process_file* newfile = malloc (sizeof(struct process_file));
  // release_lock ();

  /* If the file could be opened, set the return value (eax) to -1.*/
  /* Modify the exit_code to -1 and exit the thead. */
  if (open_file == NULL || newfile == NULL) {
    f-> eax = -1;
    thread_current ()->exit_code = -1;
    return;
  }

    struct inode *inode = file_get_inode (open_file);
    if(inode != NULL && inode_is_dir(inode))
     {
      newfile->dir = dir_open( inode );
    }  else  {  
       newfile->dir = NULL;
    }

    /* Set the file descriptor for newfile and push it into the open_files list of the current thread.*/
    /* Return the file descriptor. */
    newfile -> file = open_file;
    newfile -> fd = thread_current() -> file_descriptor;
    (thread_current () -> file_descriptor)++;
    list_push_back (&(thread_current () -> open_files), &newfile->elem);
    f->eax =  newfile -> fd;
}


/* Returns the size of the file open in bytes.*/
void filesize_sys (struct intr_frame *f){
  int * p = f->esp;

  /* Invalid address. */
  /* Set the return value (eax) to -1. */
  /* Modify the exit_code to -1 and exit the thead. */
  if (check_addr (p+1) == 0){
    f->eax = -1;
    thread_current ()->exit_code = -1;
    thread_exit ();
    return;
  }
  // acquire_lock ();
  /* Traverse the open_files list of the current thread to find the file with given file descriptor. */
  struct list_elem *tmp = list_begin (&(thread_current()->open_files));
  for (tmp; tmp != list_end(&(thread_current()->open_files));tmp = list_next(tmp)){
    struct process_file * proc_file = list_entry(tmp, struct process_file , elem);
    if (proc_file -> fd == *(p+1)){
      /* If the file with the given file descriptor is invalid, we modify the exit_code and exit the thread.*/
      if (proc_file== NULL) {
        // release_lock ();
        f->eax = -1;
        thread_current ()->exit_code = -1;
        thread_exit ();
        return;
      }
      /* Get the size of file. */
      /* Use lock to assure the synchronozation. */
      f->eax = file_length (proc_file->file);
      break;
    }
  }
  // release_lock ();
}


/* Reads size bytes from the file open as fd into buffer. */
void read_sys (struct intr_frame *f){
  int * p = f->esp;

  /* Invalid address. */
  /* Set the return value (eax) to -1. */
  /* Modify the exit_code to -1 and exit the thead. */
  if (check_addr (p+1) == 0 || check_addr (p+2) == 0 || (valid_string (*((char **) ((char *)f->esp + 8))) == false) || check_addr (p+3) == 0) {
    f->eax = -1;
    thread_current ()->exit_code = -1;
    thread_exit ();
    return;
  }

  /* Special case: fd = 0. (STDIN_FILENO)*/
  /* Read from the keyboard. */
  if (*(p+1) == 0) {
    int  position = 0;
    for (position; position < *(p+3); position++){
      *(uint8_t *)(*(p+2) + position) = input_getc();
    }
    f->eax = *(p+3);

  /* Special case: fd = 1. (STDOUT_FILENO)*/
  /* Invalid in syscall read.*/
  /* Modify the exit_code and return.*/
  }  else if  (*(p+1) == 1 ) {
    f->eax = -1;
    thread_current ()->exit_code = -1;
    thread_exit ();

  /* Nornal case. */
  } else {
    // acquire_lock();
    /* Traverse the open_files list of the current thread to find the file with given file descriptor. */
    struct list_elem *tmp = list_begin (&(thread_current()->open_files));
    struct process_file * proc_file = list_entry(tmp, struct process_file , elem);
    for (tmp; tmp != list_end(&(thread_current()->open_files)); tmp = list_next(tmp)){
      proc_file = list_entry(tmp, struct process_file , elem);
      /* If the file with the given file descriptor is invalid, we modify the exit_code and exit the thread.*/
      if (proc_file -> fd == *(p+1)){
          if (proc_file == NULL){
            // release_lock();
            f->eax = -1;
            thread_current()->exit_code = -1;
            thread_exit ();
            return;
        }

        /* Read the file.*/
        /* Use lock to assure the synchronization. */
        f->eax = file_read(proc_file -> file,(void*)*((char **) ((char *)f->esp + 8)),*((unsigned *)f->esp + 3));
        break;
      }
    }
    // release_lock();
  }
}


/*Writes size bytes from buffer to the open file fd. */
void write_sys(struct intr_frame *f){

  /* Invalid address. */
  /* Set the return value (eax) to -1. */
  /* Modify the exit_code to -1 and exit the thead. */
  int * p = f->esp;
  if (check_addr (p+1) == 0 || check_addr (p+2) == 0 || (valid_string (*((char **) ((char *)f->esp + 8))) == false) || check_addr (p+3) == 0){
    f->eax = -1;
    thread_current ()->exit_code = -1;
    thread_exit ();
    return;
  }

  /* Special case: fd = 1 (STDOUT_FILENO)*/
  /* Output the content of buffer to the console. */
  if (*(p+1) == 1){
      putbuf( (const char*)*(p+2),(off_t)*(p+3));
      f->eax = *(p+3);
      return;
  } else {
    // acquire_lock();
    /* Traverse the open_files list of the current thread to find the file with given file descriptor. */
    struct list_elem *tmp = list_begin (&(thread_current()->open_files));
    for (tmp; tmp != list_end(&(thread_current()->open_files)); tmp = list_next(tmp)){
      struct process_file * proc_file = list_entry(tmp, struct process_file , elem);

      /* If the file with the given file descriptor is invalid, we modify the exit_code and exit the thread.*/
      if (proc_file -> fd == *(p+1)){
        if (proc_file == NULL) {
          f->eax = 0 ;
          // release_lock();
          thread_current()->exit_code = -1;
          thread_exit ();
          return;
        }

        /* Write the file.*/
        /* Use lock to assure the synchronization. */
        f->eax = file_write(proc_file -> file, (const char*)*(p+2), (off_t)*(p+3));
        break;
      }
    }
    // release_lock();
  }

}


/* Changes the next byte to be read or written in open file fd to position. */
void seek_sys(struct intr_frame *f){
  int * p = f->esp;

  /* Invalid address. */
  /* Set the return value (eax) to -1. */
  /* Modify the exit_code to -1 and exit the thead. */
  if (check_addr(p+1) == 0 || check_addr(p+2) == 0){
    thread_current()->exit_code = -1;
    thread_exit ();
    return;
  }

  // acquire_lock();
 /* Traverse the open_files list of the current thread to find the file with given file descriptor. */
  struct list_elem *tmp = list_begin (&(thread_current()->open_files));
    for (tmp; tmp != list_end(&(thread_current()->open_files)); tmp = list_next(tmp)){
      struct process_file * proc_file = list_entry(tmp, struct process_file , elem);
      if (proc_file -> fd == *(p+1)){

      /* If the file with the given file descriptor is invalid, we modify the exit_code and exit the thread.*/
      if (proc_file -> fd == *(p+1)){
        if (proc_file == NULL) {
          // release_lock();
          f->eax = 0 ;
          thread_current()->exit_code = -1;
          thread_exit ();
          return;
        }

        /* Use lock to assure the synchronization. */
        file_seek(proc_file->file,*(p+2));
        break;
      }
    }
  }
  // release_lock();
}

/*Returns the position of the next byte to be read or written in open file fd*/
void tell_sys(struct intr_frame *f){
  int * p = f->esp;
  if (check_addr(p+1) == 0){
    f->eax = -1;
    thread_current()->exit_code = -1;
    thread_exit ();
    return;
  }
    /* Traverse the open_files list of the current thread to find the file with given file descriptor. */
  // acquire_lock();
  struct list_elem *tmp = list_begin (&(thread_current()->open_files));
  for (tmp; tmp != list_end(&(thread_current()->open_files)); tmp = list_next(tmp)){
    struct process_file * proc_file = list_entry(tmp, struct process_file , elem);
    if (proc_file -> fd == *(p+1)){

      /* If the file with the given file descriptor is invalid, we modify the exit_code and exit the thread.*/
      if (proc_file == NULL){
        // release_lock();
        f->eax = -1;
        thread_current()->exit_code = -1;
        thread_exit ();
        return;
      }
      /* Use lock to assure the synchronization. */
      f->eax = file_tell(proc_file->file);
      break;
    }
  }
  // release_lock();
}


/*Closes file descriptor fd.*/
void close_sys(struct intr_frame *f){
  int * p = f->esp;
  if (check_addr(p+1) == 0){
    thread_current()->exit_code = -1;
    thread_exit ();
    return;
  }
  // /* Traverse the open_files list of the current thread to find the file with given file descriptor. */
  struct list_elem *tmp = list_begin (&(thread_current()->open_files));
  struct process_file * proc_file = list_entry(tmp, struct process_file , elem);
  for (tmp; tmp != list_end(&(thread_current()->open_files)); tmp = list_next(tmp)){
    proc_file = list_entry(tmp, struct process_file , elem);
    // if (proc_file -> fd == *(p+1) ||  *(p+1) == -1 ){
        if (*(p+1) == proc_file->fd)
        {
          file_close(proc_file->file);

         //remove dir from file desc
          if(proc_file->dir){
              dir_close(proc_file->dir);
          }
          list_remove(&proc_file->elem);
          free(proc_file);
          if (*(p+1) != -1)  {  return;  }
        }
  }
}



void chdir_sys (struct intr_frame *f ){
  int * p = f->esp;
  if ((check_addr (p+1) == false) || (valid_string (*((char **) ((char *)f->esp + 4))) == false)){
      thread_current()->exit_code = -1;
      thread_exit ();
      f->eax = false;
      return;
  }
  bool success = false;
  // acquire_lock();
  success = dir_chdir (*(p+1));
  // release_lock();
  f->eax = success;
}


void mkdir_sys (struct intr_frame *f){
  int * p = f->esp;
  bool success = false;
  if ((check_addr (p+1) == false)  || (valid_string (*((char **) ((char *)f->esp + 8))) == false) ){
      thread_current()->exit_code = -1;
      f->eax = false;
      thread_exit ();
      return;
  }

  block_sector_t sector;
  // acquire_lock();
  if(free_map_allocate (1, &sector))
  success = dir_create(sector,1,*(p+1));
  // release_lock();
  f->eax = success;
}


void readdir_sys (struct intr_frame *f){
  int * p = f->esp;
  if ((check_addr (p+1) == false)  || (valid_string (*((char **) ((char *)f->esp + 8))) == false) ){
      thread_current()->exit_code = -1;
      f->eax = false;
      thread_exit ();
      return;
  }

  struct list_elem *tmp = list_begin (&(thread_current()->open_files));
  struct process_file * proc_file = list_entry(tmp, struct process_file , elem);
  for (tmp; tmp != list_end(&(thread_current()->open_files));tmp = list_next(tmp)){
    proc_file = list_entry(tmp, struct process_file , elem);
    if (proc_file -> fd == *(p+1)){
      /* If the file with the given file descriptor is invalid, we modify the exit_code and exit the thread.*/
      if (proc_file== NULL) {
        f->eax = false;
        thread_current ()->exit_code = -1;
        thread_exit ();
        return;
      }
      /* Get the size of file. */
      /* Use lock to assure the synchronozation. */
      struct inode *inode = file_get_inode(proc_file->file); // file descriptor -> inode
     if(inode == NULL || ! inode_is_dir(inode)){
        // release_lock();
        thread_current()->exit_code = -1;
        f->eax = false;
        thread_exit ();
        return;
     }
     // release_lock();
     f->eax = dir_readdir (proc_file->dir, *(p+2));
    }
  }

}


void isdir_sys (struct intr_frame *f){

  int * p = f->esp;
  // bool success;
  if (check_addr (p+1) == 0){
    thread_current()->exit_code = -1;
    f->eax = false;
    thread_exit ();
     return;
  }

	// acquire_lock();
  struct list_elem *tmp = list_begin (&(thread_current()->open_files));
  struct process_file * proc_file = list_entry(tmp, struct process_file , elem);

  for (tmp; tmp != list_end(&(thread_current()->open_files));tmp = list_next(tmp)){
    proc_file = list_entry(tmp, struct process_file , elem);

    if (proc_file -> fd == *(p+1)){
      /* If the file with the given file descriptor is invalid, we modify the exit_code and exit the thread.*/
      if (proc_file== NULL) {
        f->eax = false;
        thread_current ()->exit_code = -1;
        thread_exit ();
        return;
      }

    	f->eax =  inode_is_dir (file_get_inode(proc_file->file));

    }
  }
}


void inumber_sys (struct intr_frame *f){
  int * p = f->esp;
  if (check_addr (p+1) == 0){
    f->eax = -1;
    thread_current()->exit_code = -1;
     thread_exit ();
     return;
  }

  struct list_elem *tmp = list_begin (&(thread_current()->open_files));
  struct process_file * proc_file = list_entry(tmp, struct process_file , elem);

  for (tmp; tmp != list_end(&(thread_current()->open_files));tmp = list_next(tmp)){
    proc_file = list_entry(tmp, struct process_file , elem);

    if (proc_file -> fd == *(p+1)){
      /* If the file with the given file descriptor is invalid, we modify the exit_code and exit the thread.*/
      if (proc_file== NULL) {
        f->eax = false;
        thread_current ()->exit_code = -1;
        thread_exit ();
        return;
      }

    	f->eax = inode_get_inumber (file_get_inode(proc_file->file));

    }
  }
}





