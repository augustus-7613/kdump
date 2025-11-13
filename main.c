#include <stdio.h>
#include <stdlib.h>
#include <krb5.h>
#include <unistd.h>
#include <libgen.h>
#include <string.h>

#include "src/printing.h"
#include "src/types.h"
#include "src/utils.h"

int main(int argc, char** argv)
{
    krb5_context ctx = {0};
    krb5_ccache ccache = {0};
    krb5_cc_cursor cursor = {0};
    krb5_creds creds = {0};
    krb5_error_code ret = {0};
    krb5_ticket *ticket = NULL;
    const char *msg = NULL;
    int opt = 0;
    args_t args = {0};
    const char* base = basename(argv[0]);

    while ((opt = getopt(argc, argv, "Hc:vh")) != -1)
    {
        switch (opt)
        {
            case 'H':
                args.hashcat = 1;
                break;
            case 'c':
                args.ccache = optarg;
                break;
            case 'v':
                args.verbose = PRINT_VERBOSE;
                break;
            case 'h':
                usage(base);
                break;
            default:
                break;
        }
    }

    if ((ret = krb5_init_context(&ctx)) != 0) goto error;

    if (args.ccache == NULL)
    {
        if ((ret = krb5_cc_default(ctx, &ccache)) != 0) goto error;
    }
    else
    {
        const size_t len = strlen(args.ccache);
        char* ccache_path = malloc(6 + len);
        strcpy(ccache_path, "FILE:");
        strcat(ccache_path, args.ccache);
        if ((ret = krb5_cc_resolve(ctx, ccache_path, &ccache)))
        {
            free(ccache_path);
            goto error;
        }
        free(ccache_path);
    }

    if ((ret = krb5_cc_start_seq_get(ctx, ccache, &cursor)) != 0) goto error;

    while (krb5_cc_next_cred(ctx, ccache, &cursor, &creds) == 0)
    {
        if (creds.ticket.data == NULL || creds.ticket.length == 0) continue;

        if ((ret = krb5_decode_ticket(&creds.ticket, &ticket)) != 0)
        {
            msg = krb5_get_error_message(ctx, ret);
            fprintf(stderr, "%s: %s\n", base, msg);
            krb5_free_error_message(ctx, msg);
            ticket = NULL;
        }

        print_krb5_cred(&creds, ticket, &args);

        krb5_free_ticket(ctx, ticket);
        krb5_free_cred_contents(ctx, &creds);
    }

    krb5_cc_end_seq_get(ctx, ccache, &cursor);
    krb5_cc_close(ctx, ccache);
    krb5_free_context(ctx);

    return 0;
error:
    msg = krb5_get_error_message(ctx, ret);
    fprintf(stderr, "%s: %s\n", base, msg);
    krb5_free_error_message(ctx, msg);
    krb5_cc_close(ctx, ccache);
    krb5_free_context(ctx);
    return 1;
}
