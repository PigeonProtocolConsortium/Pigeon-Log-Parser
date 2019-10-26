#include "pigeon_parser.h"

#include <stdio.h>

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