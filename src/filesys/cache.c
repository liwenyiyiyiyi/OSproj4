#include "filesys/cache.h"
#include <stdio.h>
#include "devices/block.h"
#include <string.h>
#include <bitmap.h>
#include <list.h>


#define WRITE_BACK_FREQ   5 /* in terms of seconds */
#define CACHE_WRITE_INTV (1 * TIMER_FREQ)
#define DEBUG 0

static struct lock cache_lock;
extern struct block *fs_device;
static struct lock ahead_lock;
static struct list ahead_queue;
static struct condition ahead_cond;

#define BUFFER_CACHE_SIZE 64

static struct buffer_cache_entry cache[BUFFER_CACHE_SIZE];
static int hand = 0;

/*struct for cache read ahead*/
struct ahead_entry {
    block_sector_t sector;
    struct list_elem elem;
};

/* initializes buffer cache related structures */
void
buffer_cache_init (void)
{
    list_init(&ahead_queue);
    lock_init(&ahead_lock);
    lock_init(&cache_lock);
    cond_init(&ahead_cond);
    for (int i = 0; i < BUFFER_CACHE_SIZE; i++){
        struct buffer_cache_entry *current = &cache[i];
        lock_init(&current->buffer_entry_lock);
        current->valid = false;
    }
    thread_create("write_behind", PRI_DEFAULT, buffer_cache_write_back, NULL);
    thread_create("read_ahead", PRI_DEFAULT, buffer_cache_read_ahead, NULL);
}


/* to search for a specific buffur cache */
struct buffer_cache_entry* buffer_cache_lookup (block_sector_t sector){
    for (int i =0; i < BUFFER_CACHE_SIZE; i++){
        if (   cache[i].sector_index == sector && cache[i].valid){
            return &cache[i];
        }
    }
    /* Return NULL if there is a cache miss. */
    return NULL;
}


/* writes size bytes to buffer cache in sector at offset sector_ofs. if buffer cache
 * is full, evicts a sector
 * if zeroed flag is true, the sector is zeroed out first before copying
 * buffer into it */

void
buffer_cache_write (block_sector_t sector, const void *buffer,off_t size, off_t offset)
{

    lock_acquire(&cache_lock);
    struct buffer_cache_entry* buffer_found = buffer_cache_lookup(sector);

    /* Eviction */
    while (buffer_found == NULL){
        buffer_found = buffer_cache_evict();
        /* Successful Eviction */
        if (buffer_found != NULL){

            /* Initialize some info. */
            buffer_found -> valid = true;
            buffer_found -> dirty = false;
             buffer_found -> sector_index = sector;
            lock_init(&buffer_found->buffer_entry_lock);

            /* Read from fs_device into data*/
            lock_acquire(&buffer_found->buffer_entry_lock);
            block_read(fs_device,sector,buffer_found->data);
            lock_release(&buffer_found->buffer_entry_lock);
            break;
        }
    }

    buffer_found->accessed = true;
    buffer_found->dirty = true;
    memcpy (buffer_found->data+offset,buffer,size);
    lock_release(&cache_lock);
}

/* first checks if the block at sector is present in cache. if preset, reads the sector data of
 * size bytes at offset sector_ofs into buffer and returns true. otherwise brings it in cache.
   buffer must have enough bytes i.e. BLOCK_SECTOR_SIZE - sector_ofs */


void
buffer_cache_read (block_sector_t sector, void *buffer,off_t size, off_t offset)
{

    lock_acquire(&cache_lock);
    struct buffer_cache_entry* buffer_found = buffer_cache_lookup(sector);

    /* Eviction */
    while (buffer_found == NULL){
        buffer_found = buffer_cache_evict();
        /* Successful Eviction */
        if (buffer_found != NULL){

            /* Initialize some info. */
            buffer_found -> valid = true;
            buffer_found -> dirty = false;
            buffer_found -> sector_index = sector;
            lock_init(&buffer_found->buffer_entry_lock);

            /* Read from fs_device into data*/
            lock_acquire(&buffer_found->buffer_entry_lock);
            block_read(fs_device,sector,buffer_found->data);
            lock_release(&buffer_found->buffer_entry_lock);
            break;
        }
    }

    buffer_found->accessed = true;
    /* TODO diff from memcpy and memset */

    memcpy (buffer, buffer_found->data+offset, size);
    lock_release(&cache_lock);
}

/* evicts a sector from the buffer cache and returns its entry num */
struct buffer_cache_entry*
buffer_cache_evict ()
{
    while (cache[hand].accessed && cache[hand].valid){
        cache[hand].accessed = false;
        hand = (hand+1)%BUFFER_CACHE_SIZE;
    }

    struct buffer_cache_entry *evivted = &cache[hand];
    evivted -> valid = true;
    hand = (hand+1)%BUFFER_CACHE_SIZE;

    /* If the cache to be evicted is dirty, write the data into disk. */
    if (evivted->dirty){
        block_write(fs_device, evivted->sector_index,evivted->data);
        evivted-> dirty = false;
    }
    return evivted;
}


void buffer_cache_write_back_part(){
        for (int i = 0; i < BUFFER_CACHE_SIZE ; i++){
            lock_acquire(&cache[i].buffer_entry_lock);

            /* If entry is valid & dirty -> flush into disk. */
            if (cache[i].valid && cache[i].dirty){
                block_write(fs_device, cache[i].sector_index, cache[i].data);
                /* Set the dirty to false. */
                cache[i].dirty = false;
            }
            lock_release(&cache[i].buffer_entry_lock);
    }
}

/* Achieve cache write behind*/
 void buffer_cache_write_back() {
    while (true) {
        timer_sleep(CACHE_WRITE_INTV);

        /* Flush all cache. */
        for (int i = 0; i < BUFFER_CACHE_SIZE ; i++){
          lock_acquire(&cache[i].buffer_entry_lock);
          /* If entry is valid & dirty -> flush into disk. */
          if (cache[i].valid && cache[i].dirty){
            block_write(fs_device, cache[i].sector_index, cache[i].data);
            /* Set the dirty to false. */
            cache[i].dirty = false;
          }
          lock_release(&cache[i].buffer_entry_lock);
        }
    }
    NOT_REACHED();
}

/* Achieve cache read ahead*/
 void buffer_cache_read_ahead(void *aux UNUSED) {
    while (true) {
        lock_acquire(&ahead_lock);
        while (list_empty(&ahead_queue)){ 
          cond_wait(&ahead_cond, &ahead_lock);
        }
        struct ahead_entry *a_entry = list_entry(list_pop_front(&ahead_queue),struct ahead_entry, elem);
        lock_release(&ahead_lock);
        block_sector_t sector = a_entry->sector;
        buffer_cache_read(sector, NULL,BLOCK_SECTOR_SIZE,0);
        free(a_entry);
    }
    NOT_REACHED();
}

/* to send conditional signal*/
void cache_read_ahead_put(block_sector_t sector) {
    lock_acquire(&ahead_lock);
    struct ahead_entry *a_entry = malloc(sizeof(struct ahead_entry));
    a_entry->sector = sector;
    cond_signal(&ahead_cond, &ahead_lock);

    list_push_back(&ahead_queue, &a_entry->elem);
    lock_release(&ahead_lock);
}



 