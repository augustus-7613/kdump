#pragma once

typedef enum
{
    PRINT_HASHCAT_FORMAT    = 1 << 0,
    PRINT_VERBOSE           = 1 << 1
} PRINT_OPTIONS;

typedef struct
{
    uint8_t hashcat;
    char* ccache;
    uint8_t verbose;
} args_t;

extern args_t args;