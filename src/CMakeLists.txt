cmake_minimum_required(VERSION 2.6)

project(pigeon_parser)
add_library(pigeon_parser pigeon_parser.c pigeon_list.c pigeon_string.c pigeon_memory.c)

project(parser_test)
add_executable(parser_test main.c)
target_link_libraries(parser_test pigeon_parser)