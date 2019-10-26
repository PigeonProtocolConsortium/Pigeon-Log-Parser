
#include "pigeon_parser.h"
#include "pigeon_string.h"
#include "pigeon_memory.h"
#include "pigeon_list.h"

#include <stdio.h>
#include <ctype.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

static const char encoding_str_sha256[] = "sha256";
static const char encoding_str_ed25519[] = "ed25519";

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
        pigeon_parse_error(ctx, "EOF encountered when ':' expected");
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
    {
        pigeon_parse_error(ctx, "EOF encountered when expecting encoded hash value");
        return false;
    }

    pos = ctx->msg_pos;
    const char * hash_end = pigeon_scan_base64(ctx);
    decoded->hash = pigeon_strdup_range(pos, hash_end - pos);

    pigeon_move_to(ctx, hash_end);
    return true;
}

static bool pigeon_parse_string(pigeon_parse_context_t * restrict ctx, char ** restrict str)
{
    if (ctx->remaining == 0)
    {
        pigeon_parse_error(ctx, "EOF encountered when expecting string");
        return false;
    }

    pigeon_advance_pos(ctx, 1);

    pigeon_string_t tmp_str;
    if (!pigeon_string_init(&tmp_str))
    {
        pigeon_parse_error(ctx, "memory allocation failed");
        return false;
    }

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
                {
                    char seq[3] = { '\\', *pos, '\0' };
                    pigeon_parse_error(ctx, "unsupported escape sequence ('%s') in string", seq);
                    goto error;
                }
            }
            else
            {
                pigeon_parse_error(ctx, "EOF encountered while in string literal");
                goto error;
            }
        }
        else if (isprint(*pos))
        {
            pigeon_string_append_ch(&tmp_str, *pos);
            ++pos;
        }
        else if (*pos == '\n')
        {
            pigeon_parse_error(ctx, "expected '\"' marker before end of line");
            goto error;
        }
        else
        {
            pigeon_parse_error(ctx, "invalid character 0x%ux encountered in string", *pos);
            goto error;
        }
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
    {
        pigeon_parse_error(ctx, "EOF encountered when expecting field value");
        return false;
    }

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

    if (!isdigit(*ctx->msg_pos))
    {
        pigeon_parse_error(ctx, "invalid character '%c' in field value", *ctx->msg_pos);
        return false;
    }
    
    field->field_type = PIGEON_FIELD_INT64;

    char number[64];
    unsigned length = 0;

    const char * pos = ctx->msg_pos;
    const char * end = ctx->msg_pos + ctx->remaining;

    for (; pos != end && length < sizeof(number) - 1; ++pos)
    {
        if (isdigit(*pos) || *pos == '-')
            number[length++] = *pos;
        else
            break;
    }

    if (length == sizeof(number))
    {
        pigeon_parse_error(ctx, "length of integer literal exceeds limit (%u)", (unsigned)(sizeof(number) - 1));
        return false;
    }

    number[length] = '\0';

    const char* endp;
    field->field_value.int64_ = strtol(number, (char**)&endp, 10);
    if (*endp != '\0')
    {
        pigeon_parse_error(ctx, "invalid integer literal '%s'", number);
        return false;
    }

    pigeon_move_to(ctx, pos);
    return true;
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
    {
        pigeon_parse_error(ctx, "invalid character '%c' in field name", *ctx->msg_pos);
        return false;
    }
    else if (ctx->remaining == 0)
    {
        pigeon_parse_error(ctx, "EOF encountered when header/footer field expected");
        return false;
    }

    pigeon_skip_ws(ctx);

    if (!pigeon_parse_field_value(ctx, field))
        return false;

    pigeon_skip_ws(ctx);

    if (ctx->remaining == 0)
    {
        pigeon_parse_error(ctx, "EOF encountered when end of line expected");
        return false;
    }
    else if (*ctx->msg_pos != '\n')
    {
        pigeon_parse_error(ctx, "invalid character '%c' encountered instead of end of line", *ctx->msg_pos);
        return false;
    }

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
        {
            pigeon_parse_error(ctx, "author header requires IDENTITY value type");
            goto error;
        }
    }
    else if (strcmp(field.field_name, header_sequence) == 0)
    {
        if (field.field_type == PIGEON_FIELD_INT64)
        {
            decoded_msg->sequence_number = field.field_value.int64_;
            pigeon_release_field_value(&field);
        }
        else
        {
            pigeon_parse_error(ctx, "sequence header requires INT64 value type");
            goto error;
        }
    }
    else if (strcmp(field.field_name, header_kind) == 0)
    {
        if (field.field_type == PIGEON_FIELD_STRING)
        {
            decoded_msg->kind = field.field_value.string;
            pigeon_release_field_value(&field);
        }
        else
        {
            pigeon_parse_error(ctx, "kind header requires STRING value type");
            goto error;
        }
    }
    else if (strcmp(field.field_name, header_previous) == 0)
    {
        if (field.field_type == PIGEON_FIELD_SIGNATURE)
        {
            decoded_msg->previous = field.field_value.encoded;
            pigeon_release_field_value(&field);
        }
        else
        {
            pigeon_parse_error(ctx, "previous header requires SIGNATURE value type");
            goto error;
        }
    }
    else if (strcmp(field.field_name, header_timestamp) == 0)
    {
        if (field.field_type == PIGEON_FIELD_INT64)
        {
            decoded_msg->timestamp = field.field_value.int64_;
            pigeon_release_field_value(&field);
        }
        else
        {
            pigeon_parse_error(ctx, "timestamp header requires INT64 value type");
            goto error;
        }
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
    {
        pigeon_parse_error(ctx, "EOF encountered when data field or newline expected");
        return false;
    }
    else if (*ctx->msg_pos != ':')
    {
        pigeon_parse_error(ctx, "expeted ':' after data field name");
        return false;
    }

    pigeon_advance_pos(ctx, 1);
    pigeon_skip_ws(ctx);

    if (!pigeon_parse_field_value(ctx, field))
        return false;

    pigeon_skip_ws(ctx);

    if (ctx->remaining == 0)
    {
        pigeon_parse_error(ctx, "EOF encountered when end of line expected");
        return false;
    }
    else if (*ctx->msg_pos != '\n')
    {
        pigeon_parse_error(ctx, "invalid character '%c' encountered instead of end of line", *ctx->msg_pos);
        return false;
    }

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
        {
            pigeon_parse_error(ctx, "memory allocation failed");
            return false;
        }

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
    {
        pigeon_parse_error(ctx, "invalid footer field name '%s'", field.field_name);
        goto error;
    }
    else if (field.field_type != PIGEON_FIELD_SIGNATURE)
    {
        pigeon_parse_error(ctx, "signature footer requires SIGNATURE value type");
        goto error;
    }

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
    {
        pigeon_parse_error(ctx, "EOF encountered before footer");
        return false;
    }
    else if (*ctx->msg_pos != '\n')
    {
        // shouldn't be able to get here without a new line present
        pigeon_parse_error(ctx, "internal parser error occurred");
        return false;
    }

    ++ctx->line_number;
    pigeon_advance_pos(ctx, 1);

    if (!pigeon_parse_footer(ctx, decoded_msg))
        goto error;

    if (ctx->remaining > 0)
    {
        pigeon_parse_error(ctx, "extra characters found when expected EOF");
        goto error;  // extra data at end
    }

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
