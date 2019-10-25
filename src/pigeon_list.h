#ifndef PIGEON_LIST_H
#define PIGEON_LIST_H

#include <stddef.h>

typedef struct pigeon_list_elem_t {
    struct pigeon_list_elem_t * next;
} pigeon_list_elem_t;

typedef struct pigeon_list_t {
    pigeon_list_elem_t * head;
    pigeon_list_elem_t * tail;
} pigeon_list_t;

static inline void pigeon_list_init(pigeon_list_t * restrict plist)
{
    plist->head = plist->tail = NULL;
}

static inline void * pigeon_list_head(pigeon_list_t * plist)
{
    return plist->head;
}

static inline void * pigeon_list_tail(pigeon_list_t * plist)
{
    return plist->tail;
}

static inline void * pigeon_list_next(void * elem)
{
    return ((pigeon_list_elem_t *)elem)->next;
}

void pigeon_list_append(pigeon_list_t * restrict plist, void * elem);

static inline void * pigeon_list_pop_head(pigeon_list_t * restrict plist)
{
    pigeon_list_elem_t * elem = plist->head;
    if (elem != NULL)
    {
        plist->head = elem->next;
        elem->next = NULL;
    }

    return elem;
}

#endif