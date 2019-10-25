#include "pigeon_memory.h"
#include <stdlib.h>
#include <string.h>

void * pigeon_malloc(size_t size)
{
    return malloc(size);
}

void * pigeon_realloc(void * ptr, size_t new_size)
{
    return realloc(ptr, new_size);
}

void pigeon_free(void * ptr)
{
    free(ptr);
}
