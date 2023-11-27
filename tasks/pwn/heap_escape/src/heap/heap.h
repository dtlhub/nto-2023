#include <stdio.h>
#include <stdlib.h>
#define HEAP_INIT_ERR 0xde
#define HEAPSIZE 4096*100 //0x64000
#define NOT_INITIALIZED 0x50
#define OFFSET sizeof(size_t)
#define MALLOC_ERROR 0x80
#define ALCERR -1
#define OUT_OF_HEAP -2
typedef unsigned int wonderful_pointer;

typedef struct chunk{
    size_t size;
    //if freed
    wonderful_pointer fd_offset; 
    //last bit of size is flag. i if freed, 0 if allocated
}chunk;

typedef struct smartbin{
    size_t size;
    wonderful_pointer next;
    //pointer to the next chunk
}smartbin;

typedef struct Heap{
    size_t heap_size;
    void* heap_base;
    chunk* next_chunk;
    chunk* current_chunk;
}Heap;

wonderful_pointer wonderful_malloc(size_t size);

void wonderful_free(wonderful_pointer pointer);

Heap* init(size_t size);

int safe_write(wonderful_pointer pointer,char* buffer,size_t size);

int safe_read(wonderful_pointer pointer,char* buffer,size_t size);

static void smartbin_put(smartbin* bin,wonderful_pointer chunk);

static wonderful_pointer smartbin_get(smartbin* bin);

static smartbin* smartbin_init(size_t size);

