#include "pigeon_string.h"
#include "pigeon_memory.h"
#include <stdlib.h>
#include <string.h>

bool pigeon_string_init(pigeon_string_t * restrict str)
{
    str->ptr = NULL;
    str->length = 0;
    str->capacity = 0;
    return true;
}

void pigeon_string_free(pigeon_string_t * restrict str)
{
    free(str->ptr);
    str->ptr = NULL;
    str->length = 0;
    str->capacity = 0;
}

bool pigeon_string_expand_to(pigeon_string_t * restrict str, size_t new_capacity)
{
    void * new_ptr = pigeon_realloc(str->ptr, new_capacity);
    if (!new_ptr)
        return false;

    str->ptr = new_ptr;
    str->capacity = new_capacity;
    return true;
}

bool pigeon_string_expand(pigeon_string_t * restrict str)
{
    size_t capacity = str->capacity;
    if (capacity != 0)
        capacity = capacity * 3 / 2;
    else
        capacity = PIGEON_MIN_STRING_SIZE;

    return pigeon_string_expand_to(str, capacity);
}

bool pigeon_string_append_ch(pigeon_string_t * restrict str, char ch)
{
    if (str->length == str->capacity)
    {
        if (!pigeon_string_expand(str))
            return false;
    }

    str->ptr[str->length] = ch;
    ++str->length;
    return true;
}

const char * pigeon_string_cstr(pigeon_string_t * restrict str)
{
    if (str->capacity == 0)
        return "";

    if (str->length + 1 > str->capacity)
    {
        if (!pigeon_string_expand(str))
            return NULL;
    }

    str->ptr[str->length] = '\0';
    return str->ptr;
}

char * pigeon_string_release(pigeon_string_t * restrict str)
{
    if (str->capacity == 0)
        return NULL;

    char * ptr = (char *)pigeon_string_cstr(str);
    str->ptr = NULL;
    str->capacity = str->length = 0;
    return ptr;
}

char * pigeon_strdup_range(const char * restrict str, size_t size)
{
    char * copy = pigeon_malloc(size + 1);
    if (!copy)
        return NULL;

    memcpy(copy, str, size);
    copy[size] = '\0';
    return copy;
}