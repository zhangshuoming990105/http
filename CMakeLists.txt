cmake_minimum_required(VERSION 3.16)
project(http C)

set(CMAKE_C_STANDARD 11)

include_directories(.)
link_libraries(event ssl crypto event_openssl)
add_executable(http
        http_func.c
        http_func.h
        https_server.c
        ssl_func.c
        ssl_func.h)
