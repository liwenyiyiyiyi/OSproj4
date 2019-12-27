#ifndef FILESYS_FILESYS_H
#define FILESYS_FILESYS_H

#include <stdbool.h>
#include "filesys/off_t.h"

/* Sectors of system file inodes. */
#define FREE_MAP_SECTOR 0       /* Free map file inode sector. */
#define ROOT_DIR_SECTOR 1       /* Root directory file inode sector. */

/* Block device that contains the file system. */
struct block *fs_device;
struct parse_result{
  char* name;
  struct dir* dir;
  int status;  /* 1 for all found; 2 for inner missed(valid for create); 3 for error*/
};
void filesys_init (bool format);
void filesys_done (void);
bool filesys_create (const char *name, off_t initial_size);
struct file *filesys_open (const char *name);
bool filesys_remove (const char *name);
char *get_filename (const char *);
struct parse_result* parse (const char *path);

#endif /* filesys/filesys.h */