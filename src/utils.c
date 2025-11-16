#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void usage(const char* progname)
{
    fprintf(stderr, "Usage: %s [-h] [-c] [-v] [-m] [-H]\n", progname);
    fprintf(stderr, "\t-h Help menu\n");
    fprintf(stderr, "\t-c Specifies credential cache\n");
    fprintf(stderr, "\t-v Verbose\n");
    fprintf(stderr, "\t-m Expand magic number. Needs -v\n");
    fprintf(stderr, "\t-p Password used to decrypt the encrypted part of TGS ticket\n");
    fprintf(stderr, "\t-n NTLM hash used to decrypt the encrypted part of TGS ticket\n");
    fprintf(stderr, "\t-H Prints encrypted part of TGS ticket in hashcat format\n");
    exit(EXIT_FAILURE);
}

int hex2bytes(const char* hex, unsigned char* out, const size_t out_len)
{
    size_t i;
    const size_t hex_len = strlen(hex);
    if (hex_len != out_len * 2) return 1;
    for (i = 0; i < out_len; ++i)
        if (sscanf(hex + i*2, "%2hhx", &out[i]) != 1) return 1;
    return 0;
}
