#ifndef PIGEON_MEMORY_H
#define PIGEON_MEMORY_H

#include <stddef.h>

void * pigeon_malloc(size_t size);
void * pigeon_realloc(void * ptr, size_t new_size);
void pigeon_free(void * ptr);

#endif