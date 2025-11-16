#pragma once

typedef enum
{
    PRINT_HASHCAT_FORMAT    = 1 << 0,
    PRINT_VERBOSE           = 1 << 1
} PRINT_OPTIONS;

typedef struct
{
    uint8_t hashcat;
    uint8_t magic;
    uint8_t verbose;
    char* ccache;
    char* password;
} args_t;

extern args_t args;