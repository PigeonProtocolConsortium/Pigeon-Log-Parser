
#include <stdio.h>
#include <ctype.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#include "pigeon_string.h"
#include "pigeon_memory.h"
#include "pigeon_list.h"

typedef int32_t pigeon_sequence_number_t;
typedef int64_t pigeon_timestamp_t;

typedef int32_t pigeon_message_size_t;

typedef struct {
    const char * token_start;
    pigeon_message_size_t token_length;
} pigeon_token_t;

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

#define PIGEON_MAX_INTRINSIC_FIELD_NAME_LENGTH 20

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

    int line_number;
    const char * line_start;
    
    pigeon_parsed_message_t * decoded_msg;
} pigeon_parse_context_t;

static const char encoding_str_sha256[] = "sha256:";
static const char encoding_str_ed25519[] = "ed25519:";

static inline void pigeon_init_field(pigeon_field_t * restrict field)
{
    field->field_name = NULL;
    field->field_type = PIGEON_FIELD_EMPTY;
}

static void pigeon_free_field(pigeon_field_t * restrict field)
{
    pigeon_free(field->field_name);
    field->field_name = NULL;

    switch (field->field_type)
    {
        case PIGEON_FIELD_SIGNATURE:
        case PIGEON_FIELD_IDENTITY:
        case PIGEON_FIELD_BLOB:
            pigeon_free(field->field_value.encoded.hash);
            field->field_value.encoded.hash = NULL;
            break;

        case PIGEON_FIELD_STRING:
            pigeon_free(field->field_value.string);
            break;
    }

    field->field_type = PIGEON_FIELD_EMPTY;
}

static void pigeon_free_field_list(pigeon_list_t * restrict field_list)
{
    pigeon_field_t * field = (pigeon_field_t *)field_list->head;
    while (field != NULL)
    {
        pigeon_field_t * next = pigeon_list_next(field);
        pigeon_free_field(field);
        field = next;
    }

    field_list->head = field_list->tail = NULL;
}

static inline void pigeon_advance_pos(pigeon_parse_context_t * restrict ctx, pigeon_message_size_t count)
{
    ctx->msg_pos += count;
    ctx->remaining -= count;
}

static inline void pigeon_move_to(pigeon_parse_context_t * restrict ctx, const char * restrict pos)
{
    ctx->msg_pos = pos;
    ctx->remaining = ctx->msg_size - (pos - ctx->msg_data);
}

static inline bool pigeon_is_prefix(pigeon_parse_context_t * restrict ctx, const char * restrict prefix, pigeon_message_size_t prefix_length)
{
    ctx->remaining > prefix_length && 0 == strncmp(ctx->msg_pos, prefix, prefix_length);
}

static inline char * pigeon_find_eol(pigeon_parse_context_t * ctx)
{
    return memchr(ctx->msg_pos, '\n', ctx->remaining);
}

// static bool pigeon_parse_sha256(pigeon_parse_context_t * restrict ctx, unsigned char * restrict hash_value, pigeon_message_size_t hash_size)
// {
//     const char * end = pigeon_find_eol(ctx);
//     if (!end)
//         return false;

//     size_t bin_len;
//     int rc = sodium_base642bin(hash_value, hash_size, ctx->msg_pos, end - ctx->msg_pos, "", &bin_len, NULL, sodium_base64_VARIANT_URLSAFE);
//     return rc == 0 && bin_len == crypto_hash_sha256_BYTES;
// }

// static bool pigeon_parse_ed25519(pigeon_parse_context_t * restrict ctx, unsigned char * restrict hash_value, pigeon_message_size_t hash_size)
// {
//     const char * end = memchr(ctx->msg_pos, '\n', ctx->remaining);
//     if (!end)
//         return false;

//     size_t bin_len;
//     int rc = sodium_base642bin(hash_value, hash_size, ctx->msg_pos, end - ctx->msg_pos, "", &bin_len, NULL, sodium_base64_VARIANT_URLSAFE);
//     return rc == 0 && bin_len == crypto_sign_ed25519_PUBLICKEYBYTES;
// }

static inline int pigeon_safe_memcmp(const char * restrict lhs, size_t lhs_size, const char * restrict rhs, size_t rhs_size)
{
    size_t min_size = lhs_size <= rhs_size ? lhs_size : rhs_size;
    int cmp = memcmp(lhs, rhs, min_size);
    return cmp != 0 ? cmp : lhs_size - rhs_size;
}

static inline bool pigeon_token_matches(const pigeon_token_t * restrict token, const char *str, size_t str_size)
{
    return 0 == pigeon_safe_memcmp(token->token_start, token->token_length, str, str_size);
}

static inline bool pigeon_isbase64(char ch)
{
    if (isalpha(ch) || isdigit(ch))
        return true;
        
    switch (ch)
    {
        case '-':
        case '_':
        case '=':
        case '/':
        case '+':
            return true;

        default: break;
    }

    return false;
}

static const char * pigeon_scan_base64(pigeon_parse_context_t * restrict ctx)
{
    const char * end = ctx->msg_pos + ctx->remaining;
    for (const char * pos = ctx->msg_pos; pos != end; ++pos)
        if (!pigeon_isbase64(*pos))
            return pos;

    return end;
}

static pigeon_message_size_t pigeon_skip_ws(pigeon_parse_context_t * restrict ctx)
{
    const char * pos = ctx->msg_pos;
    const char * end = ctx->msg_pos + ctx->remaining;

    while (pos != end && (*pos == ' ' || *pos == '\t'))
        ++pos;

    pigeon_message_size_t skipped_bytes = pos - ctx->msg_pos;
    pigeon_move_to(ctx, pos);
    return skipped_bytes;
}

// static void pigeon_skip_ws_and_eol(pigeon_parse_context_t * restrict ctx)
// {
//     const char * pos = ctx->msg_pos;
//     const char * end = ctx->msg_pos + ctx->remaining;

//     for (; pos != end; ++pos)
//     {
//         switch (*pos)
//         {
//             case ' ':
//             case '\t':
//                 break;

//             case '\n':
//                 ++ctx->line_number;
//                 ctx->line_start = pos + 1;
//                 break;
//         }
//     }

//     pigeon_move_to(ctx, pos);
// }

static bool pigeon_parse_encoded_value(pigeon_parse_context_t * restrict ctx, pigeon_encoded_value_t * restrict decoded)
{
    if (ctx->remaining == 0)
        false;

    const char * restrict pos = ctx->msg_pos;
    const char * restrict end = ctx->msg_pos + ctx->remaining;

    for (; pos != end; ++pos)
    {
        if (*pos == ':')
            break;
        else if (isspace(*pos) || !isprint(*pos))
            return false;
    }

    if (pos == end)
        return false;

    ++pos;
    pigeon_message_size_t spec_size = pos - ctx->msg_pos;
    if (0 == pigeon_safe_memcmp(ctx->msg_pos, spec_size, encoding_str_sha256, sizeof(encoding_str_sha256) - 1))
        decoded->encoding_type = PIGEON_ENCODING_TYPE_SHA256;
    else if (0 == pigeon_safe_memcmp(ctx->msg_pos, spec_size, encoding_str_ed25519, sizeof(encoding_str_ed25519) - 1))
        decoded->encoding_type = PIGEON_ENCODING_TYPE_ED25519;
    else
        return false;

    if (pos == end)
        return false;

    pigeon_move_to(ctx, pos);

    const char * hash_end = pigeon_scan_base64(ctx);
    decoded->hash = pigeon_strdup_range(pos, hash_end - pos);

    pigeon_move_to(ctx, hash_end);
    return true;
}

static bool pigeon_parse_encoded_value2(pigeon_parse_context_t * restrict ctx, pigeon_encoding_type_t * restrict encoding_type, pigeon_token_t * restrict hash)
{
    if (ctx->remaining == 0)
        false;

    const char * restrict pos = ctx->msg_pos;
    const char * restrict end = ctx->msg_pos + ctx->remaining;

    for (; pos != end; ++pos)
    {
        if (*pos == ':')
        {
            pigeon_message_size_t spec_size = pos - ctx->msg_pos;
            if (0 == pigeon_safe_memcmp(ctx->msg_pos, spec_size, encoding_str_sha256, sizeof(encoding_str_sha256) - 1))
                *encoding_type = PIGEON_ENCODING_TYPE_SHA256;
            else if (0 == pigeon_safe_memcmp(ctx->msg_pos, spec_size, encoding_str_ed25519, sizeof(encoding_str_ed25519) - 1))
                *encoding_type = PIGEON_ENCODING_TYPE_ED25519;
            else
                return false;

            break;
        }
        else if (isspace(*pos) || !isprint(*pos))
            return false;
    }

    if (pos == end)
        return false;

    pigeon_move_to(ctx, pos);

    const char * hash_end = pigeon_scan_base64(ctx);
    hash->token_start = pos;
    hash->token_length = hash_end - pos;

    pigeon_move_to(ctx, hash_end);
    return true;
}

static bool pigeon_parse_string(pigeon_parse_context_t * restrict ctx, char ** restrict str)
{
    if (ctx->remaining < 2)
        return false;
    else if (*ctx->msg_pos != '"')
        return false;

    pigeon_advance_pos(ctx, 1);

    pigeon_string_t tmp_str;
    if (!pigeon_string_init(&tmp_str))
        return false;

    const char * pos = ctx->msg_pos;
    const char * end = ctx->msg_pos + ctx->remaining;
    while (pos != end)
    {
        if (*pos == '"')
        {
            ++pos;
            break;
        }
        else if (*pos == '\\')
        {
            if (++pos != end)
            {
                if (*pos == '"')
                    pigeon_string_append_ch(&tmp_str, '"');
                else
                    goto error;
            }
            else
                goto error;
        }
        else if (isprint(*pos))
        {
            pigeon_string_append_ch(&tmp_str, *pos);
            ++pos;
        }
        else
            goto error;
    }

    *str = pigeon_string_release(&tmp_str);
    pigeon_advance_pos(ctx, pos - ctx->msg_pos);
    return true;
    
error:
    pigeon_string_free(&tmp_str);
    return false;
}

static inline pigeon_field_type_t pigeon_deduce_field_type(char ch)
{
    switch (ch)
    {
        case '@': return PIGEON_FIELD_IDENTITY;
        case '&': return PIGEON_FIELD_BLOB;
        case '%': return PIGEON_FIELD_SIGNATURE;
    }

    // Shouldn't ever get here
    return PIGEON_FIELD_STRING;
}

static bool pigeon_parse_field_value(pigeon_parse_context_t * restrict ctx, pigeon_field_t * restrict field)
{
    if (ctx->remaining == 0)
        return false;

    switch (*ctx->msg_pos)
    {
        case '@':
        case '&':
        case '%':
            field->field_type = pigeon_deduce_field_type(*ctx->msg_pos);
            pigeon_advance_pos(ctx, 1);
            return pigeon_parse_encoded_value(ctx, &field->field_value.encoded);

        case '"':
            field->field_type = PIGEON_FIELD_STRING;
            return pigeon_parse_string(ctx, &field->field_value.string);

        default:
            break;
    }

    if (isdigit(*ctx->msg_pos))
    {
        field->field_type = PIGEON_FIELD_INT64;

        char number[64];
        unsigned length = 0;

        const char * pos = ctx->msg_pos;
        const char * end = ctx->msg_pos + ctx->remaining;

        for (; pos != end && length < sizeof(number); ++pos)
        {
            if (isdigit(*pos) || *pos == '-')
                number[length++] = *pos;
            else
                break;
        }

        if (length == sizeof(number))
        {
            // Number was too large
            return false;
        }

        number[length] = '\0';

        const char* endp;
        field->field_value.int64_ = strtol(number, (char**)&endp, 10);
        if (*endp != '\0')
        {
            // Invalid number
            return false;
        }

        pigeon_move_to(ctx, pos);
        return true;
    }

    return false;
}

void pigeon_scan_bareword(pigeon_parse_context_t * restrict ctx)
{
    const char * pos = ctx->msg_pos;
    const char * end = ctx->msg_pos + ctx->remaining;

    for (; pos != end; ++pos)
        if (!isalpha(*pos))
            break;

    pigeon_move_to(ctx, pos);
}

// typedef struct {
//     const char *name;
//     size_t name_size;
//     pigeon_field_type_t type;
// } pigeon_header_footer_field_desc_t;

static const char header_author[] = "author";
static const char header_sequence[] = "sequence";
static const char header_kind[] = "kind";
static const char header_previous[] = "previous";
static const char header_timestamp[] = "timestamp";

// static const pigeon_header_footer_field_desc_t header_fields_descriptors[] = {
//     { header_author,    sizeof(header_author),      PIGEON_FIELD_IDENTITY },
//     { header_sequence,  sizeof(header_sequence),    PIGEON_FIELD_INT64 },
//     { header_kind,      sizeof(header_kind),        PIGEON_FIELD_STRING },
//     { header_previous,  sizeof(header_previous),    PIGEON_FIELD_SIGNATURE },
//     { header_timestamp, sizeof(header_timestamp),   PIGEON_FIELD_INT64 }
// };

bool pigeon_parse_header_or_footer(pigeon_parse_context_t * restrict ctx, pigeon_field_t * restrict field)
{
    const char * field_name_start = ctx->msg_pos;
    pigeon_scan_bareword(ctx);
    field->field_name = pigeon_strdup_range(field_name_start, ctx->msg_pos - field_name_start);

    if (0 == pigeon_skip_ws(ctx))
        return false;  // No whitespace
    else if (ctx->remaining == 0)
        return false;  // unexpected EOF

    return pigeon_parse_field_value(ctx, field);
}

bool pigeon_parse_header(pigeon_parse_context_t * restrict ctx, pigeon_parsed_message_t * restrict decoded_msg)
{

    // for (unsigned i = 0; i < sizeof(header_fields_descriptors) / sizeof(header_fields_descriptors[0]); ++i)
    // {
    //     pigeon_skip_ws(ctx);
    //     if (pigeon_is_prefix(ctx, header_fields_descriptors[i].name, header_fields_descriptors[i].name_size))
    //     {
    //         pigeon_advance_pos(ctx, header_fields_descriptors[i].name_size);
    //         if (header_fields_descriptors[i].name == header_author)
    //         {
    //             pigeon_encoding_type_t encoding_type;
    //             pigeon_parse_encoded_value2(ctx, )
    //         }
    //     }
    // }

    pigeon_field_t field;
    pigeon_init_field(&field);
    if (!pigeon_parse_header_or_footer(ctx, &field))
        goto error;

    if (strcmp(field.field_name, header_author) == 0)
    {
        if (field.field_type == PIGEON_FIELD_IDENTITY)
            decoded_msg->author = field.field_value.encoded;
        else
            goto error;
    }
    else if (strcmp(field.field_name, header_sequence) == 0)
    {
        if (field.field_type == PIGEON_FIELD_INT64)
            decoded_msg->sequence_number = field.field_value.int64_;
        else
            goto error;
    }
    else if (strcmp(field.field_name, header_kind) == 0)
    {
        if (field.field_type == PIGEON_FIELD_STRING)
            decoded_msg->kind = field.field_value.string;
        else
            goto error;
    }
    else if (strcmp(field.field_name, header_previous) == 0)
    {
        if (field.field_type == PIGEON_FIELD_SIGNATURE)
            decoded_msg->previous = field.field_value.encoded;
        else
            goto error;
    }
    else if (strcmp(field.field_name, header_timestamp) == 0)
    {
        if (field.field_type == PIGEON_FIELD_INT64)
            decoded_msg->timestamp = field.field_value.int64_;
        else
            goto error;
    }
    else
        goto error;

    pigeon_skip_ws(ctx);
    if (ctx->remaining != 0 && *ctx->msg_pos == '\n')
    {
        pigeon_advance_pos(ctx, 1);
        ++ctx->line_number;
    }

    return true;

error:
    pigeon_free_field(&field);
    return false;
}

bool pigeon_parse_data_field(pigeon_parse_context_t * restrict ctx, pigeon_field_t * restrict field)
{
    if (!pigeon_parse_string(ctx, &field->field_name))
        return false;

    pigeon_skip_ws(ctx);

    if (ctx->remaining == 0)
        return false;     // unexpected EOF
    else if (*ctx->msg_pos != ':')
        return false;     // expected ':'

    pigeon_advance_pos(ctx, 1);
    pigeon_skip_ws(ctx);

    if (!pigeon_parse_field_value(ctx, field))
        return false;

    if (ctx->remaining != 0 && *ctx->msg_pos == '\n')
    {
        pigeon_advance_pos(ctx, 1);
        ++ctx->line_number;
    }

    return true;
}

bool pigeon_parse_message(const char * restrict msg_data, pigeon_message_size_t msg_size, pigeon_parsed_message_t * restrict decoded_msg)
{
    memset(decoded_msg, 0, sizeof(*decoded_msg));

    pigeon_parse_context_t ctx;
    ctx.msg_data = msg_data;
    ctx.msg_size = msg_size;
    ctx.msg_pos = msg_data;
    ctx.remaining = msg_size;
    ctx.line_number = 1;
    ctx.line_start = msg_data;

    while (ctx.remaining > 0)
    {
        pigeon_skip_ws(&ctx);
        if (*ctx.msg_pos == '\n')
            break;
        else if (!pigeon_parse_header(&ctx, decoded_msg))
            goto error;
    }

    if (ctx.remaining == 0)
        goto error; // unexpected EOF
    else if (*ctx.msg_pos != '\n')
        goto error; // expected blank line

    pigeon_advance_pos(&ctx, 1);

    if (ctx.remaining == 0)
        goto error; // unexpected EOF
    
    pigeon_list_init(&decoded_msg->fields);

    while (ctx.remaining > 0)
    {
        pigeon_skip_ws(&ctx);
        if (*ctx.msg_pos == '\n')
            break;

        pigeon_field_t * field = malloc(sizeof(pigeon_field_t));
        if (!field)
            goto error; // allocation failure

        pigeon_init_field(field);
        if (!pigeon_parse_data_field(&ctx, field))
        {
            pigeon_free_field(field);
            pigeon_free(field);
            goto error;
        }

        pigeon_list_append(&decoded_msg->fields, field);
    }

    // pigeon_skip_ws(&ctx);
    // if (ctx.remaining == 0)
    //     return false;

    // while (ctx.remaining > 0)
    // {

    // }

    // pigeon_parse_header(&ctx, decoded_msg);

    return true;

error:
    // TODO: free decoded_msg
    return false;
}

static const char test_message[] = 
    "author @ed25519:ajgdylxeifojlxpbmen3exlnsbx8buspsjh37b/ipvi=\n"
    "sequence 23\n"
    "kind \"example\"\n"
    "previous %sha256:85738f8f9a7f1b04b5329c590ebcb9e425925c6d0984089c43a022de4f19c281\n"
    "timestamp 23123123123\n"
    "\n"
    "\"foo\": &sha256:3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea\n"
    "\"baz\":\"bar\""
    "\"my_friend\":@ed25519:abcdef1234567890"
    "\"really_cool_message\":%sha256:85738f8f9a7f1b04b5329c590ebcb9e425925c6d0984089c43a022de4f19c281"
    "\"baz\":\"whatever\""
    "\n";

static const char* format_encoded_value(const pigeon_encoded_value_t * restrict value)
{
    static char buffer[256];

    const char * type = "(unknown)";
    switch (value->encoding_type)
    {
        case PIGEON_ENCODING_TYPE_ED25519: type = "ED25519"; break;
        case PIGEON_ENCODING_TYPE_SHA256: type = "SHA256"; break;
    }

    snprintf(buffer, sizeof(buffer), "%s (%s)", value->hash, type);
    return buffer;
}

int main(void)
{
    pigeon_parsed_message_t message;
    if (!pigeon_parse_message(test_message, sizeof(test_message) - 1, &message))
    {
        puts("Parsing failed\n");
        return 1;
    }

    puts("==== HEADER ====");
    printf("author: %s\n", format_encoded_value(&message.author));
    printf("sequence: %u\n", message.sequence_number);
    printf("kind: %s\n", message.kind);
    printf("previous: %s\n", format_encoded_value(&message.previous));
    printf("timestamp: %ld\n", message.timestamp);

    puts("\n==== DATA FIELDS ====");
    pigeon_field_t * field = pigeon_list_head(&message.fields);
    for (; field != NULL; field = pigeon_list_next(field))
    {
        printf("%s = ", field->field_name);
        switch (field->field_type)
        {
            case PIGEON_FIELD_IDENTITY:
            case PIGEON_FIELD_BLOB:
            case PIGEON_FIELD_SIGNATURE:
                printf("%s\n", format_encoded_value(&field->field_value.encoded));
                break;

            case PIGEON_FIELD_INT64:
                printf("%ld\n", field->field_value.int64_);
                break;

            case PIGEON_FIELD_STRING:
                printf("[%s]\n", field->field_value.string);
                break;

            default:
                puts("(error)\n");
                break;
        }
    }
    

    return 0;
}