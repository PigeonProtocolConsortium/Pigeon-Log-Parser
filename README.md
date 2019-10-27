# Pigeon Log Parser

A C library that parses textual pigeon log entries.

# Project Status

It works! Things may change very rapidly as the protocol spec evolves.

# Build

```
cd pigeon-spec/src
cmake -DCMAKE_BUILD_TYPE=Debug .
make
./parser_test < test_messages/message.1.txt
```
