#ifndef CACHE_FILESYS_H
#define CACHE_FILESYS_H
#include <stdio.h>
#include <list.h>
#include "off_t.h"
#include "devices/block.h"
#include "devices/timer.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/malloc.h"

#define BUFFER_CACHE_SIZE   64 /* in terms of sectors */

/* struct for buffur cache entry*/
struct buffer_cache_entry
  {
    struct list_elem elem;                               /*buffut entry list entry*/
    bool valid;                                                      /*valid bit*/
    bool accessed;                                              /* accessed bit */
    bool dirty;                                                       /* dirty bit */
    char data[BLOCK_SECTOR_SIZE];       /* buffur entry data*/
    block_sector_t sector_index;                 /* sector number */
    struct lock buffer_entry_lock;               /* buffur entry lock*/
  };

void buffer_cache_init (void);
void buffer_cache_write (block_sector_t , const void *,off_t, off_t);
void buffer_cache_read (block_sector_t , void *,off_t, off_t);
struct buffer_cache_entry* buffer_cache_evict ();
struct buffer_cache_entry* buffer_cache_lookup (block_sector_t);
void buffer_cache_write_back ();
void buffer_cache_write_back_part ();
void cache_read_ahead_put(block_sector_t sector);
 void buffer_cache_read_ahead(void *aux UNUSED) ;

#endif /* CACHE_FILESYS_H */