cmake_minimum_required(VERSION 3.10)

project(kdump C)

set(CMAKE_C_STANDARD 90)
set(CMAKE_C_STANDARD_REQUIRED True)

add_executable(${PROJECT_NAME}
        main.c
        src/printing.c
        src/printing.h
        src/types.h
        src/utils.c
        src/utils.h
)

target_link_libraries(${PROJECT_NAME} krb5 k5crypto)