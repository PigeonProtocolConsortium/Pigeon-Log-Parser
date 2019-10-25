#include "pigeon_list.h"

void pigeon_list_append(pigeon_list_t * restrict plist, void * elem)
{
    ((pigeon_list_elem_t*)elem)->next = NULL;

    if (plist->tail != NULL)
    {
        plist->tail->next = elem;
        plist->tail = elem;
    }
    else
    {
        plist->head = elem;
        plist->tail = elem;
    }
    
}
