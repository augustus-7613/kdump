#include <stdio.h>
#include <stdlib.h>

void usage(const char* progname)
{
    fprintf(stderr, "Usage: %s [-h] [-c] [-v] [-H]\n", progname);
    fprintf(stderr, "\t-h help menu\n");
    fprintf(stderr, "\t-c specifies credential cache\n");
    fprintf(stderr, "\t-v verbose\n");
    fprintf(stderr, "\t-H prints TGS in hashcat format\n");
    exit(EXIT_FAILURE);
}
