#ifndef PIGEON_PARSER_H
#define PIGEON_PARSER_H

#include "pigeon_list.h"
#include <stdbool.h>
#include <stdint.h>

typedef int32_t pigeon_sequence_number_t;
typedef int64_t pigeon_timestamp_t;
typedef int32_t pigeon_message_size_t;

typedef enum {
    PIGEON_ENCODING_TYPE_SHA256,
    PIGEON_ENCODING_TYPE_ED25519
} pigeon_encoding_type_t;

typedef struct {
    pigeon_encoding_type_t encoding_type;
    char * hash;
} pigeon_encoded_value_t;

typedef enum {
    PIGEON_FIELD_EMPTY,
    PIGEON_FIELD_STRING,
    PIGEON_FIELD_INT64,
    PIGEON_FIELD_IDENTITY,
    PIGEON_FIELD_SIGNATURE,
    PIGEON_FIELD_BLOB
} pigeon_field_type_t;

typedef struct {
    pigeon_list_elem_t elem;

    char * field_name;
    pigeon_field_type_t field_type;

    union {
        pigeon_encoded_value_t encoded;
        char * string;
        int64_t int64_;
    } field_value;
} pigeon_field_t;

typedef struct {
    pigeon_encoded_value_t author;
    pigeon_sequence_number_t sequence_number;
    char * kind;
    pigeon_encoded_value_t previous;
    pigeon_timestamp_t timestamp;
    pigeon_encoded_value_t signature;

    pigeon_list_t fields;
} pigeon_parsed_message_t;

typedef struct {
    const char * msg_data;
    const char * msg_pos;
    pigeon_message_size_t msg_size;
    pigeon_message_size_t remaining;

    unsigned line_number;
    const char * line_start;

    char error_messages[256];
} pigeon_parse_context_t;

bool pigeon_parse_message(pigeon_parse_context_t * restrict ctx, const char * restrict msg_data, pigeon_message_size_t msg_size, pigeon_parsed_message_t * restrict decoded_msg);

void pigeon_free_parsed_message(pigeon_parsed_message_t * restrict msg);

static inline const char * pigeon_get_error_messages(const pigeon_parse_context_t * restrict ctx)
{
    return ctx->error_messages;
}

#endif