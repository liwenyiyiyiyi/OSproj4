#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "filesys/free-map.h"

#define DEBUG 0
/* A directory. */
struct dir 
  {
    struct inode *inode;                /* Backing store. */
    off_t pos;                          /* Current position. */
    bool safe_to_del;                   /* prevent deletion if open or cwd of a process */
  };

/* A single directory entry. */
struct dir_entry 
  {
    block_sector_t inode_sector;        /* Sector number of header. */
    char name[NAME_MAX + 1];            /* Null terminated file name. */
    bool in_use;                        /* In use or free? */
  };

/* Creates a directory with space for ENTRY_CNT entries in the
   given SECTOR.  Returns true if successful, false on failure. */
bool
dir_create (block_sector_t sector, size_t entry_cnt, char *path)
{
  /* create root */
  if ((path[strlen (path) - 1] == '/') && (strlen (path) == 1))
    {
      inode_create (sector, entry_cnt, true, ROOT_DIR_SECTOR);
      return true;
    }

  /* remove trailing '/' */
  if (path[strlen (path) - 1] == '/')
    path[strlen (path )- 1] = '\0';

  struct parse_result *result = parse(path);
  char *dir_to_create = result -> name;
  struct dir *dir = result ->dir;
  if (!dir | !dir_to_create){
    if (result->name){free(result->name);}
    free(result);
    return false;
  }

  block_sector_t parent = inode_get_inumber (dir_get_inode (dir));

  bool success = (inode_create (sector, entry_cnt, true, parent)
                  && dir_add (dir, dir_to_create, sector));
  free(result->name);
  free (result);

  return success;
}

/* Opens and returns the directory for the given INODE, of which
   it takes ownership.  Returns a null pointer on failure. */
struct dir *
dir_open (struct inode *inode)
{
  struct dir *dir = calloc (1, sizeof *dir);
  if (inode != NULL && dir != NULL)
    {
      dir->inode = inode;
      dir->pos = 0;
      dir->safe_to_del = false;
      return dir;
    }
  else
    {
      inode_close (inode);
      free (dir);
      return NULL; 
    }
}

/* Opens the root directory and returns a directory for it.
   Return true if successful, false on failure. */
struct dir *
dir_open_root (void)
{
  return dir_open (inode_open (ROOT_DIR_SECTOR));
}

/* Opens and returns a new directory for the same inode as DIR.
   Returns a null pointer on failure. */
struct dir *
dir_reopen (struct dir *dir) 
{
  return dir_open (inode_reopen (dir->inode));
}

/* Destroys DIR and frees associated resources. */
void
dir_close (struct dir *dir) 
{
  if (dir != NULL)
    {
      /* open_cnt gets decremented in inode_close */
      if (dir->inode != NULL)
        if (inode_open_count(dir->inode) == 1)
          dir->safe_to_del = true;

      inode_close (dir->inode);
      free (dir);
    }
}

/* Returns the inode encapsulated by DIR. */
struct inode *
dir_get_inode (struct dir *dir) 
{
  return dir->inode;
}

/* Searches DIR for a file with the given NAME.
   If successful, returns true, sets *EP to the directory entry
   if EP is non-null, and sets *OFSP to the byte offset of the
   directory entry if OFSP is non-null.
   otherwise, returns false and ignores EP and OFSP. */
static bool
lookup (const struct dir *dir, const char *name,
        struct dir_entry *ep, off_t *ofsp) 
{
  struct dir_entry e;
  size_t ofs;
  
  ASSERT (dir != NULL);
  ASSERT (name != NULL);
   if (DEBUG){printf("enter   nonnononn------\n");}
     ASSERT (dir->inode != NULL);
  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e)
    if (e.in_use && !strcmp (name, e.name)) 
      {
        if (ep != NULL)
          *ep = e;
        if (ofsp != NULL)
          *ofsp = ofs;
        return true;
      }
  if (DEBUG){printf("whatever false------\n");}  
  return false;
}

/* Searches DIR for a file with the given NAME
   and returns true if one exists, false otherwise.
   On success, sets *INODE to an inode for the file,otherwise to
   a null pointer.  The caller must close *INODE. */
bool
dir_lookup (const struct dir *dir, const char *name,
            struct inode **inode)
{
  struct dir_entry e;
    if (DEBUG){printf("enter lookup-------------\n");}
  if (DEBUG){printf("enter lookup-------%s-------\n",name);}
  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* if name is . */
  if (strcmp (name, ".") == 0)
    {
      *inode = inode_reopen (dir->inode);
    }
  /* parent case */
  else if (strcmp (name, "..") == 0)
    {
      dir_get_parent (dir, inode);
    }
  else
    {

      if (lookup (dir, name, &e, NULL))
        *inode = inode_open (e.inode_sector);
      else
        *inode = NULL;
    }

  return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in sector
   INODE_SECTOR.
   Returns true if successful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */
bool
dir_add (struct dir *dir, const char *name, block_sector_t inode_sector)
{
  struct dir_entry e;
  off_t ofs;
  bool success = false;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Check NAME for validity. */
  if (*name == '\0' || strlen (name) > NAME_MAX)
    return false;

  /* Check that NAME is not in use. */
  if (lookup (dir, name, NULL, NULL))
    goto done;

  /* Set OFS to offset of free slot.
     If there are no free slots, then it will be set to the
     current end-of-file.
     
     inode_read_at() will only return a short read at end of file.
     Otherwise, we'd need to verify that we didn't get a short
     read due to something intermittent such as low memory. */
  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) 
    if (!e.in_use)
      break;

  /* Write slot. */
  e.in_use = true;
  strlcpy (e.name, name, sizeof e.name);
  e.inode_sector = inode_sector;
  success = inode_write_at (dir->inode, &e, sizeof e, ofs) == sizeof e;

 done:
  return success;
}

/* Removes any entry for NAME in DIR.
   Returns true if successful, false on failure,
   which occurs only if there is no file with the given NAME. */
bool
dir_remove (struct dir *dir, const char *name) 
{
  struct dir_entry e;
  struct inode *inode = NULL;
  bool success = false;
  off_t ofs;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Find directory entry. */
  if (!lookup (dir, name, &e, &ofs))
    goto done;

  if (thread_current ()->cwd != NULL)
    if (inode_get_inumber (thread_current ()->cwd->inode) == e.inode_sector)
      return false;

  /* Open inode. */
  inode = inode_open (e.inode_sector);
  if (inode == NULL)
    goto done;

  /* Erase directory entry. */
  e.in_use = false;
  if (inode_write_at (dir->inode, &e, sizeof e, ofs) != sizeof e)
    goto done;

  /* Remove inode. */
  inode_remove (inode);
  success = true;

 done:
  inode_close (inode);
  return success;
}

/* Reads the next directory entry in DIR and stores the name in
   NAME.  Returns true if successful, false if the directory
   contains no more entries. */
bool
dir_readdir (struct dir *dir, char name[NAME_MAX + 1])
{
  struct dir_entry e;

  while (inode_read_at (dir->inode, &e, sizeof e, dir->pos) == sizeof e) 
    {
      dir->pos += sizeof e;
      if (e.in_use)
        {
          strlcpy (name, e.name, NAME_MAX + 1);
          return true;
        } 
    }
  return false;
}


/* from path, the innermost (leaf) directory is returned
 * e.g. for path /a/b/c/file, the dir struct for c will
 * be returned (dir_open is called on it)
 */
// struct dir* dir_get_leaf (const char* path)
// {
//   char s[strlen(path) + 1];
//   memcpy(s, path, strlen(path) + 1);

//   char *save_ptr, *next_token = NULL, *token = strtok_r(s, "/", &save_ptr);

//   struct dir* dir;

//   if (s[0] == '/' || !thread_current()->cwd)
//       dir = dir_open_root();
//   else
//       dir = dir_reopen(thread_current()->cwd);

//   if (token)
//       next_token = strtok_r(NULL, "/", &save_ptr);

//   while (next_token != NULL){
//       if (strcmp(token, ".") != 0){
//           struct inode *inode;
//           if (strcmp(token, "..") == 0){
//               if (!dir_get_parent(dir, &inode)){
//                   return NULL;
//               }
//           }else{
//               if (!dir_lookup(dir, token, &inode)){
//                   return NULL;
//               }
//           }


//           if (inode_is_dir(inode)){
//               dir_close(dir);
//               dir = dir_open(inode);
//           }else{
//               inode_close(inode);
//           }
//       }

//       token = next_token;
//       next_token = strtok_r(NULL, "/", &save_ptr);
//   }
//   return dir;
// }

/* Change directory by changing thread->cwd*/
bool
dir_chdir (char *path)
{
  struct parse_result *result = parse(path);
  struct dir* dir = result->dir;
  char* name  = result->name;
  if (!dir | !name){
    if (result->name){free(result->name);}
    free(result);
    return false;
  }

    struct inode *inode = NULL;
    if (!dir_lookup(dir, name, &inode) || !inode_is_dir(inode)) {
        dir_close(dir);
        free(result->name);
        free(result);
        return false;
    }
    dir_close(dir);
    dir_close(thread_current()->cwd);
    thread_current()->cwd = dir_open(inode);
    free(result->name);
    free(result);
    return true;
}


bool dir_get_parent (const struct dir* dir, struct inode **inode)
{
  block_sector_t sector = inode_get_parent(dir_get_inode(dir));
  *inode = inode_open (sector);
  return *inode != NULL;
}