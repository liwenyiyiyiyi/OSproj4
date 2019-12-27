#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "threads/init.h"
#include "threads/flags.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/interrupt.h"
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "filesys/directory.h"


static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
static void get_process_args (char *cmd, char** args, int *arg_count);

/* Starts a new thread running a user program loaded from
 FILENAME.  The new thread may be scheduled (and may even exit)
 before process_execute() returns.  Returns the new process's
 thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name)
{

  char *fn_copy1;
  tid_t tid;

  /* Create a new thread to execute FILE_NAME. */
   char* exec_name;  /* Record the name fo the forst variable. */
   char* save_ptr;   /* Saved pointer used in strtok_r. */

  /* Make a copy of FILE_NAME.     Otherwise there's a race between the caller and load(). */
  fn_copy1 = palloc_get_page (0);
  strlcpy (fn_copy1, file_name,  strlen (file_name)+1);

  /* Wrong condition handling*/
  if (fn_copy1 == NULL)
    return TID_ERROR;

   /* Malloc memory for exec_name and make a copy of file_name. */
   exec_name = malloc (strlen (file_name) + 1);
   strlcpy (exec_name, file_name, strlen (file_name) +1 );

   /* Extract command from file_name. */
   exec_name = strtok_r (exec_name," ",&save_ptr);
   tid = thread_create (exec_name, PRI_DEFAULT, start_process, fn_copy1);
   free (exec_name);

   /* Wrong condition handling*/
  if (tid == TID_ERROR){
     palloc_free_page (fn_copy1);
  } else {
     /*Block the parent thread and wait the child thread finish load*/
      sema_down (&thread_current ()->waiting);

      /*Judge whther have loaded successfully*/
      if ( thread_current ()->load_success == 0 ){
         thread_current()->exit_code = -1;
         return TID_ERROR;
      }
  }
  return tid;
}

/* A thread function that loads a user process and starts it
 running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;
  struct list_elem *e;

  struct thread *cur = thread_current();

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);

  /* update the load status and unblock the parent process */

  /* If load failed, quit. */
  palloc_free_page (file_name);
  // if (!success)
  //   thread_exit (-1);

  if (!success){
    /* Send signal to the parent that load failed. */
    cur->parent->load_success = 0;
    if (cur->parent){
      sema_up (&cur->parent->waiting);
    }
//    thread_exit ();
  } else {
    /* Send signal to the parent that load successed. */
    cur->parent->load_success = 1;
    if (cur->parent){
      sema_up (&cur->parent->waiting);
    }
  //  sema_up (&cur->parent->waiting);
  }

  /* Start the user process by simulating a return from an
   interrupt, implemented by intr_exit (in
   threads/intr-stubs.S).  Because intr_exit takes all of its
   arguments on the stack in the form of a `struct intr_frame',
   we just point the stack pointer (%esp) to our stack frame
   and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED () ;
}

/* Waits for thread TID to die and returns its exit status.  If
 it was terminated by the kernel (i.e. killed due to an
 exception), returns -1.  If TID is invalid or if it was not a
 child of the calling process, or if process_wait() has already
 been successfully called for the given TID, returns -1
 immediately, without waiting.

 This function will be implemented in problem 2-2.  For now, it
 does nothing. */


// int
// process_wait (tid_t child_tid)
// {
//     struct thread *cur = thread_current();
//     struct list_elem *e;
//     int ret = -1;
//     // lock_acquire(&cur->children_lock);
//     for (e = list_begin(&cur->children); e != list_end(&cur->children);
//          e = list_next(e)) {
//         struct child_str *child_thread = list_entry(e, struct child_str, child_elem);
//         // lock_acquire(&cs->ref_lock);
//         if (child_thread->tid == child_tid) {
//             if (!child_thread->is_waiting) {
//                 child_thread->is_waiting = 1;
//                 // lock_release(&cs->ref_lock);
//                 sema_down(&child_thread->child_sema);
//                 ret = child_thread->exit_code;
//                 // return child_thread->exit_code;
//             }
//             // else {
//                 return ret;
//             // }
//         }
//     }
// }



int
process_wait (tid_t child_tid UNUSED)
{
  /* Record the exit_code of the child_thread to be returned. */
     int ret = -1 ; 

     /* Find the thread by given tid. */
     struct child_str* child_thread = find_thread_by_tid(child_tid);

      if (!child_thread || child_thread->is_waiting ==1 || child_thread->exit_code == -1  ){
          return ret;
      }

     if (!child_thread->is_waiting) {
          child_thread->is_waiting = 1;
           sema_down(&child_thread->child_sema);
           ret = child_thread->exit_code;
       }
        return ret;
}


/* Free the current process's resources. */
void
process_exit ()
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  struct list_elem *e;

   /*close all the files the thread opened*/
 struct list *close_open_files =&( cur->open_files);
 struct list_elem *elem;
 while (!list_empty(close_open_files)){
     struct list_elem* e = list_begin (&cur->open_files);
     struct process_file *close_file = list_entry(e, struct process_file, elem);

    //  acquire_lock();
     file_close(close_file->file);
    //  release_lock();
     list_remove(e);
     free(close_file);
 }

    if ( cur ->child_ptr ->as_parent == NULL ){
             free ( &cur -> child_ptr ) ;
     }

  /* Close the executable file itself. */
   if (cur ->self != NULL){
        //  acquire_lock();
         file_close(thread_current()->self);
        //  release_lock();
         cur->self = NULL;
         cur->thread_exited =1 ;
     }

    
    /*cut up the connection with its parent*/
    if (cur->child_ptr->as_parent) {
            cur->child_ptr->exit_code = cur->exit_code;
             cur->child_ptr->as_child = false;
            sema_up(&cur->child_ptr->child_sema);
        }

    /*close all the files in the children*/
    while (!list_empty(&cur->children)) {
        struct list_elem *e = list_pop_front(&cur->children);
        struct child_str *child_thread = list_entry(e, struct child_str, child_elem);
        // lock_acquire(&cs->ref_lock);
        if (child_thread->as_child) {
            free(child_thread);
            // lock_release(&cs->ref_lock);
        }
    }

  /* Destroy the current process's page directory and switch back
   to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL)
    {
      /* Correct ordering here is crucial.  We must set
       cur->pagedir to NULL before switching page directories,
       so that a timer interrupt can't switch back to the
       process page directory.  We must activate the base page
       directory before destroying the process's page
       directory, or our active page directory will be one
       that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
 thread.
 This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
   interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
 from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
{
  unsigned char e_ident[16];
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;
  Elf32_Half e_phnum;
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
 There are e_phnum of these, starting at file offset e_phoff
 (see [ELF1] 1-6). */
struct Elf32_Phdr
{
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool
setup_stack (void **esp, const char *file_name);
static bool
validate_segment (const struct Elf32_Phdr *, struct file *);
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage, uint32_t read_bytes,
        uint32_t zero_bytes,
        bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 Stores the executable's entry point into *EIP
 and its initial stack pointer into *ESP.
 Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp)
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL)
    goto done;
  process_activate ();

  /* Make a copy of FILE_NAME.   */
  char *exec_name,*fn_copy;
  char* save_ptr ;
  fn_copy=malloc(strlen(file_name)+1);
  strlcpy (fn_copy, file_name, strlen(file_name) + 1);

 /* Error handling. */
  if (fn_copy == NULL){
    return TID_ERROR;
  }

  /* Create a new thread to execute FILE_NAME. */
  exec_name = malloc(strlen(file_name) + 1);
  strlcpy(exec_name, file_name, strlen(file_name) + 1);
  exec_name = strtok_r (exec_name, " ", &save_ptr);



  /* Open executable file. */
  // file = filesys_open ((const char *) args[0]);
    file = filesys_open (exec_name);
     if (file == NULL)
    {
      // printf ("load: %s: open failed\n",  args[0]);
      printf ("load: %s: open failed\n", exec_name);

      goto done;
    }
  file_deny_write(file);
  t->self = file;

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2
      || ehdr.e_machine != 3 || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof(struct Elf32_Phdr) || ehdr.e_phnum > 1024)
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done;
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type)
      {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file))
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                   Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE)
                                        - read_bytes);
                }
              else
                {
                  /* Entirely zero.
                   Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page, read_bytes,
                                 zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
      }
    }

  /* Set up stack. */
  // if (!setup_stack (esp, args, arg_count))
  if (!setup_stack (esp,file_name))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;
  success = true;

  done:
  /* We arrive here whether the load is successful or not. */
  return success;
}

/* load() helpers. */

static bool
install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
 FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
   user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
   address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
   Not only is it a bad idea to map page 0, but if we allowed
   it then user code that passed a null pointer to system calls
   could quite likely panic the kernel by way of null pointer
   assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
 UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 memory are initialized, as follows:

 - READ_BYTES bytes at UPAGE must be read from FILE
 starting at offset OFS.

 - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

 The pages initialized by this function must be writable by the
 user process if WRITABLE is true, read-only otherwise.

 Return true if successful, false if a memory allocation error
 or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage, uint32_t read_bytes,
        uint32_t zero_bytes, bool writable)
{
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs (upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0)
    {
      /* Calculate how to fill this page.
       We will read PAGE_READ_BYTES bytes from FILE
       and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
  return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
  {
    palloc_free_page (kpage);
    return false;
  }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable))
  {
    palloc_free_page (kpage);
    return false;
  }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
 user virtual memory. */
static bool
setup_stack (void **esp, const char *file_name)
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL)
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
      {
        *esp = PHYS_BASE;

        /* Create a new thread to execute FILE_NAME. */
        char *token,*save_ptr;
        char *fn_copy=malloc(strlen(file_name)+1);
        strlcpy (fn_copy, file_name, strlen (file_name) + 1);
        int *address = calloc (128, sizeof(int));

        /* Traverse the file name in  order and push it into the stack address. */
        int i = 0;
        for (token = strtok_r (fn_copy, " ", &save_ptr), i = 0; token != NULL; token = strtok_r (NULL, " ", &save_ptr), i++)
		        {
		           *esp -= strlen (token) + 1;
		            memcpy(*esp, token, strlen (token) + 1);
		            address[i] = *esp;
		        }
        free(fn_copy);

        /* Word Align. */
        /* Use residue to record the number of 0 we need to add to make sure Word Align to 4 bytes. */
        int residue = (int)esp % 4;
        *esp -= residue;
        int zero = 0 ;
        memcpy(*esp, &zero, residue);

        /* Write the last argument, 4 bytes of 0's. */
        *esp -= 4;
        memcpy(*esp, &zero,  sizeof(int));

         /* Push the address of the arguments to the stack. */
        int ind = i -1 ; /* Used for loop. */
        for (ind = i-1; ind >=0; ind--){
          *esp -= sizeof(char*);
          memcpy(*esp, &address[ind], sizeof(char*));
        }

        /* Push the address of arg[0] into the stack. */
        char** address_0 = (char**)(*esp);
        *esp -= sizeof(char**);
        memcpy(*esp, &address_0, sizeof(char**));

        /* Push the number of arguments into the stack. */
        *esp -= sizeof(int);
        memcpy(*esp, &i, sizeof(int));

        /* Push the return address into the stack. */
        *esp -= sizeof(int);
        memcpy(*esp, &zero, sizeof(int));
        free(address);

      }
      else
        palloc_free_page (kpage);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 virtual address KPAGE to the page table.
 If WRITABLE is true, the user process may modify the page;
 otherwise, it is read-only.
 UPAGE must not already be mapped.
 KPAGE should probably be a page obtained from the user pool
 with palloc_get_page().
 Returns true on success, false if UPAGE is already mapped or
 if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
   address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
      && pagedir_set_page (t->pagedir, upage, kpage, writable));
}


