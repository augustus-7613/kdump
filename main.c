#include <stdio.h>
#include <stdlib.h>
#include <krb5.h>
#include <unistd.h>
#include <libgen.h>
#include <string.h>

#include "src/printing.h"
#include "src/types.h"
#include "src/utils.h"

args_t args = {0};

int main(int argc, char** argv)
{
    krb5_context ctx = {0};
    krb5_ccache ccache = {0};
    krb5_cc_cursor cursor = {0};
    krb5_creds creds = {0};
    krb5_error_code ret = {0};
    krb5_keyblock service_key = {0};
    krb5_ticket *ticket = NULL;
    const char *msg = NULL;
    int opt = 0;
    const char* base = basename(argv[0]);

    while ((opt = getopt(argc, argv, "Hc:vhp:mn:")) != -1)
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
                args.verbose = 1;
                break;
            case 'h':
                usage(base);
                break;
            case 'p':
                args.password = optarg;
                break;
            case 'm':
                args.magic = 1;
                break;
            case 'n':
                args.ntlm = optarg;
                break;
            default:
                break;
        }
    }
    if (args.password != NULL && args.ntlm != NULL)
    {
        fprintf(stderr, "%s: -p (password) and -n (NTLM) cannot be used together.\n", base);
        exit(EXIT_FAILURE);
    }

    if ((ret = krb5_init_context(&ctx)) != 0) goto error;

    if (args.ccache == NULL)
    {
        const char* env_ccname = getenv("KRB5CCNAME");
        if (env_ccname != NULL)
        {
            if ((ret = krb5_cc_resolve(ctx, env_ccname, &ccache)) != 0)
                goto error;
        }
        else
        {
            if ((ret = krb5_cc_default(ctx, &ccache)) != 0)
                goto error;
        }
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

    if (args.verbose) krb5_cc_next_cred(ctx, ccache, &cursor, &creds); // skips the first "fake" entry
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

        if (args.ntlm)
        {
            unsigned char hash[16] = {0};
            if (hex2bytes(args.ntlm, hash, 16) != 0)
            {
                fprintf(stderr, "%s: invalid NTLM hash\n", base);
                continue;
            }
            krb5_keyblock key =
            {
                .enctype = ENCTYPE_ARCFOUR_HMAC,
                .length = 16,
                .contents = hash
            };
            if (krb5_decrypt_tkt_part(ctx, &key, ticket) != 0) fprintf(stderr, "%s: failed to decrypt with NTLM hash\n", base);
        }

        if (args.password)
        {
            krb5_data pwd =
            {
                .data = args.password,
                .length = strlen(args.password)
            };
            krb5_data salt = {0};

            if (ticket->enc_part.enctype == ENCTYPE_ARCFOUR_HMAC && krb5_principal2salt(ctx, creds.server, &salt) == 0)
            {
                if (ticket != NULL && krb5_c_string_to_key(ctx, ticket->enc_part.enctype, &pwd, &salt, &service_key) == 0)
                {
                    if (krb5_decrypt_tkt_part(ctx, &service_key, ticket) != 0)
                    {
                        fprintf(stderr, "%s: failed to decrypt with password\n", base);
                    }
                }
                krb5_free_data_contents(ctx, &salt);
            }
            krb5_free_keyblock_contents(ctx, &service_key);
        }

        print_krb5_cred(ctx, &creds, ticket);

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
