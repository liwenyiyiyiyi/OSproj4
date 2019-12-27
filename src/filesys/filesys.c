#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "filesys/cache.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include <string.h>

#define DEBUG 0
/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  free_map_init ();

  buffer_cache_init ();

  if (format) 
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  free_map_close ();

  /* write back dirty data from cache */
  buffer_cache_write_back ();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */

struct parse_result*
parse (const char *path){
  /* Initialize return structure. */
  if (DEBUG){printf("-------enter--------%s--------\n",path);}
  struct parse_result *result;
  result = malloc(sizeof *result);
  result -> dir = NULL;
  result ->name  = "";
  char *buf;
  char* last;


/* TODO can't deal with '///' case */
  /* Deal with trailing '/'. */
  // char *buf = malloc(strlen(path)+1);
  // memcpy(buf, path, strlen(path)+1;
  // char* last =  buf + len - 1;

  // /* Invalid filename. */
  // if (last == '/'){
  //   result -> name = NULL;
  // }

  // /* Remove the redudant slashes. */
  // while (last == '/'){
  //   last--;
  // }
  // last++;
  // *last = '\0';
  /* Case1 : root directory */


  // char s[strlen (path) + 1];
  // char *token, *save_ptr, *prev = "";

  // memcpy(s, path, strlen (path) + 1);

  // if (path[strlen (path) - 1] == '/')
  //    return NULL;

  // for (token = strtok_r (s, "/", &save_ptr); token != NULL;
  //     token = strtok_r (NULL, "/", &save_ptr))
  //   prev = token;

  // char *ret_val = (char *) malloc ((sizeof (char)) * (strlen (prev) + 1));
  // memcpy (ret_val, prev, strlen (prev) + 1);



  // if (strlen(path) == 1 && path == '/'){
  //   result -> dir = dir_open_root();
  //   return result;
  // }

  /* Use cd to record current path. */
    struct dir *cd;

  /* Case 2: Abosolute Path.(start with '/') */
  /* Case 3: Relative Path.(not start with '/') */
    if (!thread_current()->cwd){
      if(DEBUG){printf("------case !not -------\n");}
      cd =dir_open_root(); 
    }else{
    cd = (path[0] == '/' ? dir_open_root() : dir_reopen(thread_current()->cwd));
    }
  
    /* Make a copy of path and start parsing. */
    char s[strlen(path) + 1];
    memcpy(s, path, strlen(path) + 1);
    char* token;
    char *save_ptr;
    char* prev = "";

    /* Parse. */


    for (token = strtok_r (s, "/", &save_ptr); strlen(save_ptr) != 0;token = strtok_r (NULL, "/", &save_ptr)){
      struct inode *inode;
      /* Use prev to record the parent name */
      prev = token;
      /* Special case: '..' -> parent case. */
      if (strcmp(token, "..") == 0){
        if(!dir_get_parent(cd, &inode)){
          /* Fail to get parent dir. */
          result -> dir = NULL;
          goto done;
        }

      /* Spacial case: '.' -> current directory. */
      }else if (strcmp(token, ".") == 0){
        /* Do nothing.*/
        continue;
      }

      /* Update current path(cd). */
      if (!dir_lookup(cd, token, &inode)){
          /* Fail to find the dir. */
            if(DEBUG){printf("????????why  save pointer --%s-- \n",save_ptr);}
            result -> dir = NULL;
          dir_close(cd);
          goto done;
      }

      if (inode_is_dir(inode)){
          dir_close(cd);
          cd = dir_open(inode);
      }else{
          dir_close(cd);
          inode_close(inode);
      }
    }

  result -> dir = cd;
  done:
  buf = malloc(strlen(path)+1);
  memcpy(buf, path, strlen(path)+1);
  last =  buf + strlen(path) - 1;
  /* Invalid filename. */
  if (*last == '/'){
    result -> name = NULL;
  } else {
    char *ret_val = (char *) malloc ((sizeof (char)) * (strlen (prev) + 1));
    memcpy (ret_val, token, strlen (token) + 1);
    result -> name = ret_val;
    if(DEBUG){printf("-------------out -----------%s-----\n",result -> name);}
  }
  free(buf);
  return result;
}


/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *path, off_t initial_size) 
{
  struct parse_result *result = parse(path);
  char* filename  = result -> name;
  struct dir *dir = result -> dir;
  if(DEBUG){printf("------------------filesys create----%s----\n",filename);}
  /* Error handling. */
  if (!filename || !dir){
    if(DEBUG){printf("-------wrong!--------\n");}
    if(filename){free(filename);}
    free (result);
    return false;
  }
  block_sector_t parent = inode_get_inumber (dir_get_inode (dir));
      if(DEBUG){printf("------------------filesys create--number--%d----\n",parent);}

  bool success = false;
  block_sector_t inode_sector = 0;

  if (strcmp (filename, ".") != 0 && strcmp (filename, "..") != 0)
    {
      success = (free_map_allocate (1, &inode_sector)
                      && inode_create (inode_sector, initial_size, false, parent)
                      && dir_add (dir, filename, inode_sector));
    }
  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);
  dir_close (dir);
  free(result->name);
  free (result);
  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *path)
{

  struct parse_result *result = parse(path);
  char* filename  = result -> name;
  struct dir *dir =  result->dir;
  if(DEBUG){printf("------------------filesys open----%s----\n",filename);}

  /* Error handling. */
  if (!filename || !dir){
    if(DEBUG){printf("error---------\n");}
    if(filename){free(filename);}
    free (result);
    return NULL;
  }
  struct inode *inode = NULL;
    if(DEBUG){printf("correct tmp!!!------\n");}
    dir_lookup (dir, filename, &inode);
    dir_close (dir);
    if(DEBUG){printf("correct tmp!!!--2222222222222222----\n");}
  if(filename){free(filename);}
  free (result);
    if(DEBUG){printf("correct tmp!!!----3333333333333333--\n");}
  return file_open (inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *path) 
{
	/* remove root must fail*/
	if(strlen(path)==1 && path[0]=='/')
	{
		return false;
	}

  struct parse_result *result = parse(path);
  char* filename  = result -> name;
  struct dir *dir =  result->dir;

  /* Error handling. */
  if (!filename || !dir){
    if(filename){free(result->name);}
    free(result);
    return false;
  }

  bool success = dir_remove (dir, filename) ;
  dir_close (dir);
  free(result->name);
  free(result);
  return success;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16, "/"))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}

/* returns filename from path */
char *
get_filename (const char *path)
{
  char s[strlen (path) + 1];
  char *token, *save_ptr, *prev = "";

  memcpy(s, path, strlen (path) + 1);

  if (path[strlen (path) - 1] == '/')
     return NULL;

  for (token = strtok_r (s, "/", &save_ptr); token != NULL;
      token = strtok_r (NULL, "/", &save_ptr))
    prev = token;

  char *ret_val = (char *) malloc ((sizeof (char)) * (strlen (prev) + 1));
  memcpy (ret_val, prev, strlen (prev) + 1);

  return ret_val;
}