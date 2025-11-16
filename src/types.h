#pragma once

typedef struct
{
    uint8_t hashcat;
    uint8_t magic;
    uint8_t verbose;
    char* ccache;
    char* password;
    char* ntlm;
} args_t;

extern args_t args;