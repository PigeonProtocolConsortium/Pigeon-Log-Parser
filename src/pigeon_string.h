#ifndef PIGEON_STRING_H
#define PIGEON_STRING_H

#include <stddef.h>
#include <stdbool.h>

#define PIGEON_MIN_STRING_SIZE 10

typedef struct {
    char * ptr;
    size_t length;
    size_t capacity;
} pigeon_string_t;

bool pigeon_string_init(pigeon_string_t * restrict str);

void pigeon_string_free(pigeon_string_t * restrict str);

bool pigeon_string_expand_to(pigeon_string_t * restrict str, size_t new_capacity);

bool pigeon_string_expand(pigeon_string_t * restrict str);

static inline void pigeon_string_clear(pigeon_string_t * restrict str)
{
    str->length = 0;
}

bool pigeon_string_append_ch(pigeon_string_t * restrict str, char ch);

const char * pigeon_string_cstr(pigeon_string_t * restrict str);

char * pigeon_string_release(pigeon_string_t * restrict str);

char * pigeon_strdup_range(const char * restrict str, size_t size);

#endif