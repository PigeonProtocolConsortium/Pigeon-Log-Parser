
#include <stdio.h>
#include <ctype.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

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

    unsigned line_number;
    const char * line_start;

    char error_messages[256];
} pigeon_parse_context_t;

static const char encoding_str_sha256[] = "sha256";
static const char encoding_str_ed25519[] = "ed25519";

const char * pigeon_get_error_messages(const pigeon_parse_context_t * restrict ctx)
{
    return ctx->error_messages;
}

static void pigeon_parse_error(pigeon_parse_context_t * restrict ctx, const char * format, ...)
{
    int remaining = sizeof(ctx->error_messages);
    remaining -= snprintf(ctx->error_messages, sizeof(ctx->error_messages), "Error, line %u: ", ctx->line_number);

    va_list ap;
    va_start(ap, format);
    remaining -= vsnprintf(ctx->error_messages + sizeof(ctx->error_messages) - remaining, remaining, format, ap);
    va_end(ap);

    if (remaining < 2)
        remaining = 2;

    memcpy(&ctx->error_messages[sizeof(ctx->error_messages) - remaining], "\n", 2);
}

static const char * pigeon_make_temp_str_range(const char * restrict start, const char * end)
{
    static char buffer[256];

    unsigned size = end - start;
    if (size >= sizeof(buffer) - 1)
        size = sizeof(buffer) - 1;

    memcpy(buffer, start, size);
    buffer[size] = '\0';

    return buffer;
}

static void pigeon_free_encoded_value(pigeon_encoded_value_t * restrict value)
{
    pigeon_free(value->hash);
    value->hash = NULL;
}

static inline void pigeon_init_field(pigeon_field_t * restrict field)
{
    field->elem.next = NULL;
    field->field_name = NULL;
    field->field_type = PIGEON_FIELD_EMPTY;
    memset(&field->field_value, 0, sizeof(field->field_value));
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
    pigeon_field_t * field;
    while ((field = pigeon_list_pop_head(field_list)) != NULL)
    {
        pigeon_free_field(field);
        pigeon_free(field);
    }

    field_list->head = field_list->tail = NULL;
}

static void pigeon_release_field_value(pigeon_field_t * restrict field)
{
    field->field_type = PIGEON_FIELD_EMPTY;
    memset(&field->field_value, 0, sizeof(field->field_value));
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

static inline int pigeon_safe_memcmp(const char * restrict lhs, size_t lhs_size, const char * restrict rhs, size_t rhs_size)
{
    size_t min_size = lhs_size <= rhs_size ? lhs_size : rhs_size;
    int cmp = memcmp(lhs, rhs, min_size);
    return cmp != 0 ? cmp : lhs_size - rhs_size;
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

static bool pigeon_parse_encoded_value(pigeon_parse_context_t * restrict ctx, pigeon_encoded_value_t * restrict decoded)
{
    if (ctx->remaining == 0)
        false;

    const char * algo_spec_start = ctx->msg_pos;
    const char * pos = ctx->msg_pos;
    const char * end = ctx->msg_pos + ctx->remaining;

    for (; pos != end; ++pos)
    {
        if (!isalnum(*pos))
            break;
    }

    const char * algo_spec_end = pos;

    pigeon_move_to(ctx, pos);
    pigeon_skip_ws(ctx);

    if (ctx->remaining == 0)
    {
        pigeon_parse_error(ctx, "unexpected EOF");
        return false;
    }
    else if (*ctx->msg_pos != ':')
    {
        pigeon_parse_error(ctx, "expected ':' after algorithm specifier");
        return false;
    }

    pigeon_message_size_t spec_size = algo_spec_end - algo_spec_start;
    if (0 == pigeon_safe_memcmp(algo_spec_start, spec_size, encoding_str_sha256, sizeof(encoding_str_sha256) - 1))
        decoded->encoding_type = PIGEON_ENCODING_TYPE_SHA256;
    else if (0 == pigeon_safe_memcmp(algo_spec_start, spec_size, encoding_str_ed25519, sizeof(encoding_str_ed25519) - 1))
        decoded->encoding_type = PIGEON_ENCODING_TYPE_ED25519;
    else
    {
        pigeon_parse_error(ctx, "unknown algorithm specified '%s'", pigeon_make_temp_str_range(algo_spec_start, algo_spec_end));
        return false;
    }

    pigeon_advance_pos(ctx, 1);
    pigeon_skip_ws(ctx);

    if (ctx->remaining == 0)
        return false;

    pos = ctx->msg_pos;
    const char * hash_end = pigeon_scan_base64(ctx);
    decoded->hash = pigeon_strdup_range(pos, hash_end - pos);

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

static pigeon_field_type_t pigeon_deduce_field_type(char ch)
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

    char ch = *ctx->msg_pos;
    switch (ch)
    {
        case '@':
        case '&':
        case '%':
            pigeon_advance_pos(ctx, 1);
            pigeon_skip_ws(ctx);
            field->field_type = pigeon_deduce_field_type(ch);
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

static const char header_author[] = "author";
static const char header_sequence[] = "sequence";
static const char header_kind[] = "kind";
static const char header_previous[] = "previous";
static const char header_timestamp[] = "timestamp";

bool pigeon_parse_header_or_footer(pigeon_parse_context_t * restrict ctx, pigeon_field_t * restrict field)
{
    const char * field_name_start = ctx->msg_pos;
    pigeon_scan_bareword(ctx);
    field->field_name = pigeon_strdup_range(field_name_start, ctx->msg_pos - field_name_start);

    if (0 == pigeon_skip_ws(ctx))
        return false;  // No whitespace
    else if (ctx->remaining == 0)
        return false;  // unexpected EOF

    pigeon_skip_ws(ctx);

    if (!pigeon_parse_field_value(ctx, field))
        return false;

    pigeon_skip_ws(ctx);

    if (ctx->remaining == 0)
        return false;   // unexpected EOF
    else if (*ctx->msg_pos != '\n')
        return false;   // expected newline

    pigeon_advance_pos(ctx, 1);
    ++ctx->line_number;

    return true;
}

bool pigeon_parse_header(pigeon_parse_context_t * restrict ctx, pigeon_parsed_message_t * restrict decoded_msg)
{
    pigeon_field_t field;
    pigeon_init_field(&field);
    if (!pigeon_parse_header_or_footer(ctx, &field))
        goto error;

    if (strcmp(field.field_name, header_author) == 0)
    {
        if (field.field_type == PIGEON_FIELD_IDENTITY)
        {
            decoded_msg->author = field.field_value.encoded;
            pigeon_release_field_value(&field);
        }
        else
            goto error;
    }
    else if (strcmp(field.field_name, header_sequence) == 0)
    {
        if (field.field_type == PIGEON_FIELD_INT64)
        {
            decoded_msg->sequence_number = field.field_value.int64_;
            pigeon_release_field_value(&field);
        }
        else
            goto error;
    }
    else if (strcmp(field.field_name, header_kind) == 0)
    {
        if (field.field_type == PIGEON_FIELD_STRING)
        {
            decoded_msg->kind = field.field_value.string;
            pigeon_release_field_value(&field);
        }
        else
            goto error;
    }
    else if (strcmp(field.field_name, header_previous) == 0)
    {
        if (field.field_type == PIGEON_FIELD_SIGNATURE)
        {
            decoded_msg->previous = field.field_value.encoded;
            pigeon_release_field_value(&field);
        }
        else
            goto error;
    }
    else if (strcmp(field.field_name, header_timestamp) == 0)
    {
        if (field.field_type == PIGEON_FIELD_INT64)
        {
            decoded_msg->timestamp = field.field_value.int64_;
            pigeon_release_field_value(&field);
        }
        else
            goto error;
    }
    else
        goto error;

    pigeon_free_field(&field);

    return true;

error:
    pigeon_free_field(&field);
    return false;
}

static bool pigeon_parse_data_field(pigeon_parse_context_t * restrict ctx, pigeon_field_t * restrict field)
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

    pigeon_skip_ws(ctx);

    if (ctx->remaining == 0)
        return false;   // unexpected EOF
    else if (*ctx->msg_pos != '\n')
        return false;   // expected newline

    pigeon_advance_pos(ctx, 1);
    ++ctx->line_number;

    return true;
}

bool pigeon_parse_data_fields(pigeon_parse_context_t * restrict ctx, pigeon_list_t * restrict fields)
{
    while (ctx->remaining > 0)
    {
        pigeon_skip_ws(ctx);
        if (*ctx->msg_pos == '\n')
            break;

        pigeon_field_t * field = malloc(sizeof(pigeon_field_t));
        if (!field)
            return false; // allocation failure

        pigeon_init_field(field);
        if (!pigeon_parse_data_field(ctx, field))
        {
            pigeon_free_field(field);
            pigeon_free(field);
            return false;
        }

        pigeon_list_append(fields, field);
    }

    return true;
}

bool pigeon_parse_footer(pigeon_parse_context_t * restrict ctx, pigeon_parsed_message_t * restrict decoded_msg)
{
    pigeon_field_t field;
    pigeon_init_field(&field);
    if (!pigeon_parse_header_or_footer(ctx, &field))
        goto error;
    else if (0 != strcmp(field.field_name, "signature"))
        goto error;     // invalid footer field
    else if (field.field_type != PIGEON_FIELD_SIGNATURE)
        goto error;     // signature must be SIGNATURE type

    decoded_msg->signature = field.field_value.encoded;
    pigeon_release_field_value(&field);
    pigeon_free_field(&field);
    return true;
    
error:
    pigeon_free_field(&field);
    return false;
}

bool pigeon_parse_message(pigeon_parse_context_t * restrict ctx, const char * restrict msg_data, pigeon_message_size_t msg_size, pigeon_parsed_message_t * restrict decoded_msg)
{
    memset(ctx, 0, sizeof(ctx));
    memset(decoded_msg, 0, sizeof(*decoded_msg));

    ctx->msg_data = msg_data;
    ctx->msg_size = msg_size;
    ctx->msg_pos = msg_data;
    ctx->remaining = msg_size;
    ctx->line_number = 1;
    ctx->line_start = msg_data;

    while (ctx->remaining > 0)
    {
        pigeon_skip_ws(ctx);
        if (*ctx->msg_pos == '\n')
            break;
        else if (!pigeon_parse_header(ctx, decoded_msg))
            goto error;
    }

    if (ctx->remaining == 0)
        goto error; // unexpected EOF
    else if (*ctx->msg_pos != '\n')
        goto error; // expected blank line

    ++ctx->line_number;
    pigeon_advance_pos(ctx, 1);

    if (ctx->remaining == 0)
        goto error; // unexpected EOF
    
    pigeon_list_init(&decoded_msg->fields);
    if (!pigeon_parse_data_fields(ctx, &decoded_msg->fields))
        goto error;

    if (ctx->remaining == 0)
        goto error; // unexpected EOF
    else if (*ctx->msg_pos != '\n')
        goto error; // expected blank line

    ++ctx->line_number;
    pigeon_advance_pos(ctx, 1);

    if (!pigeon_parse_footer(ctx, decoded_msg))
        goto error;

    if (ctx->remaining > 0)
        goto error;  // extra data at end

    return true;

error:
    // TODO: free decoded_msg
    return false;
}

void pigeon_free_parsed_message(pigeon_parsed_message_t * restrict msg)
{
    pigeon_free_encoded_value(&msg->author);
    pigeon_free(msg->kind);
    msg->kind = NULL;
    pigeon_free_encoded_value(&msg->previous);
    pigeon_free_encoded_value(&msg->signature);
    pigeon_free_field_list(&msg->fields);
}

static const char test_message[] = 
    "author @ed25519:ajgdylxeifojlxpbmen3exlnsbx8buspsjh37b/ipvi=\n"
    "sequence 23\n"
    "kind \"example\"\n"
    "previous %sha256:85738f8f9a7f1b04b5329c590ebcb9e425925c6d0984089c43a022de4f19c281\n"
    "timestamp 23123123123\n"
    "\n"
    "\"foo\": &sha256:3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea\n"
    "\"baz\":\"bar\"\n"
    "\"my_friend\":@ed25519:abcdef1234567890\n"
    "\"really_cool_message\":%sha256:85738f8f9a7f1b04b5329c590ebcb9e425925c6d0984089c43a022de4f19c281\n"
    "\"baz\":\"whatever\"\n"
    "\n"
    "signature %ed25519:1b04b5329c1b04b5329c1b04b5329c1b04b5329c\n";

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
    pigeon_parse_context_t ctx;
    pigeon_parsed_message_t message;
    if (!pigeon_parse_message(&ctx, test_message, sizeof(test_message) - 1, &message))
    {
        const char * msgs = pigeon_get_error_messages(&ctx);
        if (*msgs)
            puts(msgs);
        else
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

    puts("\n==== FOOTER ====");
    printf("signature: %s\n", format_encoded_value(&message.signature));
    
    fflush(stdout);

    pigeon_free_parsed_message(&message);
    return 0;
}