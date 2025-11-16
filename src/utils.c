#include <stdio.h>
#include <stdlib.h>

void usage(const char* progname)
{
    fprintf(stderr, "Usage: %s [-h] [-c] [-v] [-m] [-H]\n", progname);
    fprintf(stderr, "\t-h Help menu\n");
    fprintf(stderr, "\t-c Specifies credential cache\n");
    fprintf(stderr, "\t-v Verbose\n");
    fprintf(stderr, "\t-m Expand magic number. Needs -v\n");
    fprintf(stderr, "\t-H Prints encrypted part of TGS in hashcat format\n");
    exit(EXIT_FAILURE);
}
