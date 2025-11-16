#include <stdio.h>
#include <krb5.h>
#include <time.h>
#include <string.h>

#include "printing.h"
#include "types.h"

void print_kv_time(const int level, const char *label, const long value)
{
    char buf[32] = {0};
    const struct tm *tm_info = NULL;
    if ((tm_info = gmtime(&value)) != NULL)
    {
        strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", tm_info);
        print_kv_str(level, label, buf, strlen(buf));
    }
    else
        print_kv_int(level, label, value);
}

void print_hashcat_format(const int enctype, const char* service, const char* realm, const char* host, const unsigned char* enc_part, const size_t enc_part_len) {
    if (enctype == ENCTYPE_AES256_CTS_HMAC_SHA1_96 || enctype == ENCTYPE_AES128_CTS_HMAC_SHA1_96)
        printf("$krb5tgs$%d$<SVC-USERNAME>$%s$", enctype, realm);
    else if (enctype == ENCTYPE_ARCFOUR_HMAC )
        printf("$krb5tgs$%d$*<SVC-USERNAME>$%s$%s/%s*$", enctype, realm, service, host);

    size_t i;
    if (enctype == ENCTYPE_AES256_CTS_HMAC_SHA1_96 || enctype == ENCTYPE_AES128_CTS_HMAC_SHA1_96)
    {	    
	    for (i=enc_part_len-12; i < enc_part_len; i++) printf("%02x", enc_part[i]&0xff);
	    putchar('$');
        for (i = 0; i < enc_part_len-12; i++) printf("%02x", enc_part[i]&0xff);
    }
    else if (enctype == ENCTYPE_ARCFOUR_HMAC)
    {
	    for (i = 0; i < enc_part_len; i++)
	    {
		    if (i == 16) putchar('$');
		    printf("%02x", enc_part[i]&0xff);
	    }
    }
    putchar('\n');
}

static void print_indent(const int level)
{
    int i;
    for (i = 0; i < level; ++i) printf("    ");
}

static void print_kv_int(const int level, const char *label, const long value)
{
    print_indent(level);
    if (strcasecmp(label, "enctype") == 0)
    {
        if (value == ENCTYPE_AES128_CTS_HMAC_SHA1_96)       printf("%s: %ld (aes128-cts-hmac-sha1-96)\n", label, value);
        else if (value == ENCTYPE_AES256_CTS_HMAC_SHA1_96)  printf("%s: %ld (aes256-cts-hmac-sha1-96)\n", label, value);
        else if (value == ENCTYPE_ARCFOUR_HMAC)             printf("%s: %ld (arcfour-hmac)\n", label, value);
        else printf("%s: %ld (unknown)\n", label, value);
    }
    else if (strcasecmp(label, "ticketflags") == 0)
    {
        if (value == 0)
        {
            printf("%s: %ld\n", label, value);
            return;
        }
        printf("%s: %ld (", label, value);
        if (value & TKT_FLG_FORWARDABLE)            printf(" TKT_FLG_FORWARDABLE ");
        if (value & TKT_FLG_FORWARDED)              printf(" TKT_FLG_FORWARDED ");
        if (value & TKT_FLG_PROXIABLE)              printf(" TKT_FLG_PROXIABLE ");
        if (value & TKT_FLG_PROXY)                  printf(" TKT_FLG_PROXY ");
        if (value & TKT_FLG_MAY_POSTDATE)           printf(" TKT_FLG_MAY_POSTDATE ");
        if (value & TKT_FLG_POSTDATED)              printf(" TKT_FLG_POSTDATED ");
        if (value & TKT_FLG_INVALID)                printf(" TKT_FLG_INVALID ");
        if (value & TKT_FLG_RENEWABLE)              printf(" TKT_FLG_RENEWABLE ");
        if (value & TKT_FLG_INITIAL)                printf(" TKT_FLG_INITIAL ");
        if (value & TKT_FLG_HW_AUTH)                printf(" TKT_FLG_HW_AUTH ");
        if (value & TKT_FLG_PRE_AUTH)               printf(" TKT_FLG_PRE_AUTH ");
        if (value & TKT_FLG_TRANSIT_POLICY_CHECKED) printf(" TKT_FLG_TRANSIT_POLICY_CHECKED ");
        if (value & TKT_FLG_OK_AS_DELEGATE)         printf(" TKT_FLG_OK_AS_DELEGATE ");
        if (value & TKT_FLG_ANONYMOUS)              printf(" TKT_FLG_ANONYMOUS ");
        printf(")\n");
    }
    else if (strcasecmp(label, "magic") == 0 && args.magic)
    {
        if (value == 0)
        {
            printf("%s: %ld\n", label, value);
            return;
        }
        printf("%s: %ld (", label, value);
        if (value & KV5M_NONE)                 printf(" KV5M_NONE ");
        if (value & KV5M_PRINCIPAL)            printf(" KV5M_PRINCIPAL ");
        if (value & KV5M_DATA)                 printf(" KV5M_DATA ");
        if (value & KV5M_KEYBLOCK)             printf(" KV5M_KEYBLOCK ");
        if (value & KV5M_CHECKSUM)             printf(" KV5M_CHECKSUM ");
        if (value & KV5M_ENCRYPT_BLOCK)        printf(" KV5M_ENCRYPT_BLOCK ");
        if (value & KV5M_ENC_DATA)             printf(" KV5M_ENC_DATA ");
        if (value & KV5M_CRYPTOSYSTEM_ENTRY)   printf(" KV5M_CRYPTOSYSTEM_ENTRY ");
        if (value & KV5M_CS_TABLE_ENTRY)       printf(" KV5M_CS_TABLE_ENTRY ");
        if (value & KV5M_CHECKSUM_ENTRY)       printf(" KV5M_CHECKSUM_ENTRY ");
        if (value & KV5M_AUTHDATA)             printf(" KV5M_AUTHDATA ");
        if (value & KV5M_TRANSITED)            printf(" KV5M_TRANSITED ");
        if (value & KV5M_ENC_TKT_PART)         printf(" KV5M_ENC_TKT_PART ");
        if (value & KV5M_TICKET)               printf(" KV5M_TICKET ");
        if (value & KV5M_AUTHENTICATOR)        printf(" KV5M_AUTHENTICATOR ");
        if (value & KV5M_TKT_AUTHENT)          printf(" KV5M_TKT_AUTHENT ");
        if (value & KV5M_CREDS)                printf(" KV5M_CREDS ");
        if (value & KV5M_LAST_REQ_ENTRY)       printf(" KV5M_LAST_REQ_ENTRY ");
        if (value & KV5M_PA_DATA)              printf(" KV5M_PA_DATA ");
        if (value & KV5M_KDC_REQ)              printf(" KV5M_KDC_REQ ");
        if (value & KV5M_ENC_KDC_REP_PART)     printf(" KV5M_ENC_KDC_REP_PART ");
        if (value & KV5M_KDC_REP)              printf(" KV5M_KDC_REP ");
        if (value & KV5M_ERROR)                printf(" KV5M_ERROR ");
        if (value & KV5M_AP_REQ)               printf(" KV5M_AP_REQ ");
        if (value & KV5M_AP_REP)               printf(" KV5M_AP_REP ");
        if (value & KV5M_AP_REP_ENC_PART)      printf(" KV5M_AP_REP_ENC_PART ");
        if (value & KV5M_RESPONSE)             printf(" KV5M_RESPONSE ");
        if (value & KV5M_SAFE)                 printf(" KV5M_SAFE ");
        if (value & KV5M_PRIV)                 printf(" KV5M_PRIV ");
        if (value & KV5M_PRIV_ENC_PART)        printf(" KV5M_PRIV_ENC_PART ");
        if (value & KV5M_CRED)                 printf(" KV5M_CRED ");
        if (value & KV5M_CRED_INFO)            printf(" KV5M_CRED_INFO ");
        if (value & KV5M_CRED_ENC_PART)        printf(" KV5M_CRED_ENC_PART ");
        if (value & KV5M_PWD_DATA)             printf(" KV5M_PWD_DATA ");
        if (value & KV5M_ADDRESS)              printf(" KV5M_ADDRESS ");
        if (value & KV5M_KEYTAB_ENTRY)         printf(" KV5M_KEYTAB_ENTRY ");
        if (value & KV5M_CONTEXT)              printf(" KV5M_CONTEXT ");
        if (value & KV5M_OS_CONTEXT)           printf(" KV5M_OS_CONTEXT ");
        if (value & KV5M_ALT_METHOD)           printf(" KV5M_ALT_METHOD ");
        if (value & KV5M_ETYPE_INFO_ENTRY)     printf(" KV5M_ETYPE_INFO_ENTRY ");
        if (value & KV5M_DB_CONTEXT)           printf(" KV5M_DB_CONTEXT ");
        if (value & KV5M_AUTH_CONTEXT)         printf(" KV5M_AUTH_CONTEXT ");
        if (value & KV5M_KEYTAB)               printf(" KV5M_KEYTAB ");
        if (value & KV5M_RCACHE)               printf(" KV5M_RCACHE ");
        if (value & KV5M_CCACHE)               printf(" KV5M_CCACHE ");
        if (value & KV5M_PREAUTH_OPS)          printf(" KV5M_PREAUTH_OPS ");
        if (value & KV5M_SAM_CHALLENGE)        printf(" KV5M_SAM_CHALLENGE ");
        if (value & KV5M_SAM_CHALLENGE_2)      printf(" KV5M_SAM_CHALLENGE_2 ");
        if (value & KV5M_SAM_KEY)              printf(" KV5M_SAM_KEY ");
        if (value & KV5M_ENC_SAM_RESPONSE_ENC) printf(" KV5M_ENC_SAM_RESPONSE_ENC ");
        if (value & KV5M_ENC_SAM_RESPONSE_ENC_2) printf(" KV5M_ENC_SAM_RESPONSE_ENC_2 ");
        if (value & KV5M_SAM_RESPONSE)         printf(" KV5M_SAM_RESPONSE ");
        if (value & KV5M_SAM_RESPONSE_2)       printf(" KV5M_SAM_RESPONSE_2 ");
        if (value & KV5M_PREDICTED_SAM_RESPONSE) printf(" KV5M_PREDICTED_SAM_RESPONSE ");
        if (value & KV5M_PASSWD_PHRASE_ELEMENT) printf(" KV5M_PASSWD_PHRASE_ELEMENT ");
        if (value & KV5M_GSS_OID)              printf(" KV5M_GSS_OID ");
        if (value & KV5M_GSS_QUEUE)            printf(" KV5M_GSS_QUEUE ");
        if (value & KV5M_FAST_ARMORED_REQ)     printf(" KV5M_FAST_ARMORED_REQ ");
        if (value & KV5M_FAST_REQ)             printf(" KV5M_FAST_REQ ");
        if (value & KV5M_FAST_RESPONSE)        printf(" KV5M_FAST_RESPONSE ");
        if (value & KV5M_AUTHDATA_CONTEXT)     printf(" KV5M_AUTHDATA_CONTEXT ");
        printf(")\n");
    }
    else
        printf("%s: %ld\n", label, value);
}

static void print_kv_str(const int level, const char *label, const char* value, const unsigned int value_len)
{
    print_indent(level);
    printf("%s: ", label);
    unsigned int i = 0;
    for (i = 0; i < value_len; i++) putchar(value[i]);
    putchar('\n');
}

static void print_kv_bytes(const int level, const char *label, const unsigned char* value, const unsigned int value_len)
{
    print_indent(level);
    printf("%s: ", label);
    if (value_len == 0) printf("(nil)");
    unsigned int i = 0;
    for (i = 0; i < value_len; i++)
    {
        printf("%02x", value[i]&0xff);
        if (i == 64 && !(args.verbose & PRINT_VERBOSE))
        {
            printf("... (truncated)");
            break;
        }
    }
    putchar('\n');
}

void print_krb5_ticket(const int level, const krb5_ticket* tkt)
{
    int i;

    if (args.verbose & PRINT_VERBOSE) print_kv_int(level+1, "Magic", tkt->magic);

    print_indent(level+1); printf("Server: \n");
    if (args.verbose & PRINT_VERBOSE) print_kv_int(level+2, "Magic", tkt->server->magic);
    if (args.verbose & PRINT_VERBOSE) print_kv_int(level+2, "Length", tkt->server->length);
    print_kv_int(level+2, "Type", tkt->server->type);

    print_indent(level+2); printf("Realm: \n");
    if (args.verbose & PRINT_VERBOSE) print_kv_int(level+3, "Magic", tkt->server->realm.magic);
    if (args.verbose & PRINT_VERBOSE) print_kv_int(level+3, "Length", tkt->server->realm.length);
    print_kv_str(level+3, "Data", tkt->server->realm.data, tkt->server->realm.length);

    for (i = 0; i < tkt->server->length; i++) {
        print_indent(level+2); printf("Data[%d]: \n", i);
        if (args.verbose & PRINT_VERBOSE) print_kv_int(level+3, "Magic", tkt->server->data[i].magic);
        if (args.verbose & PRINT_VERBOSE) print_kv_int(level+3, "Length", tkt->server->data[i].length);
        print_kv_str(level+3, "Data", tkt->server->data[i].data, tkt->server->data[i].length);
    }

    print_indent(level+1); printf("Enc_part: \n");
    if (args.verbose & PRINT_VERBOSE) print_kv_int(level+2, "Magic", tkt->enc_part.magic);
    print_kv_int(level+2, "Enctype", tkt->enc_part.enctype);
    print_kv_int(level+2, "Kvno", tkt->enc_part.kvno);

    print_indent(level+2); printf("Ciphertext: \n");
    if (args.verbose & PRINT_VERBOSE) print_kv_int(level+3, "Magic", tkt->enc_part.ciphertext.magic);
    if (args.verbose & PRINT_VERBOSE) print_kv_int(level+3, "Length", tkt->enc_part.ciphertext.length);
    print_kv_bytes(level+3, "Data", tkt->enc_part.ciphertext.data, tkt->enc_part.ciphertext.length);
    if (args.hashcat)
    {
        char* service = tkt->server->data[0].data;
        service[tkt->server->data[0].length] = '\0';
        char* realm = tkt->server->realm.data;
        realm[tkt->server->realm.length] = '\0';
        char* host = "HOSTNAME";
        if (tkt->server->length > 1)
        {
            host = tkt->server->data[1].data;
            host[tkt->server->data[1].length] = '\0';
        }

        print_indent(level+3); printf("Hashcat format: ");
        print_hashcat_format(
            tkt->enc_part.enctype,
            service,
            realm,
            host,
            tkt->enc_part.ciphertext.data,
            tkt->enc_part.ciphertext.length
        );
    }

    if (tkt->enc_part2 == NULL) {
        print_indent(level+1); printf("Enc_part2: (nil)\n");
        return;
    }

    print_indent(level+1); printf("Enc_part2: \n");
    if (args.verbose & PRINT_VERBOSE) print_kv_int(level+2, "Magic", tkt->enc_part2->magic);
    print_kv_int(level+2, "Flags", tkt->enc_part2->flags);

    print_indent(level+2); printf("Client: \n");
    if (args.verbose & PRINT_VERBOSE) print_kv_int(level+3, "Magic", tkt->enc_part2->client->magic);
    if (args.verbose & PRINT_VERBOSE) print_kv_int(level+3, "Length", tkt->enc_part2->client->length);
    print_kv_int(level+3, "Type", tkt->enc_part2->client->type);

    for (i = 0; i < tkt->enc_part2->client->length; i++) {
        print_indent(level+3); printf("Data[%d]: \n", i);
        if (args.verbose & PRINT_VERBOSE) print_kv_int(level+4, "Magic", tkt->enc_part2->client->data[i].magic);
        if (args.verbose & PRINT_VERBOSE) print_kv_int(level+4, "Length", tkt->enc_part2->client->data[i].length);
        print_kv_str(level+4, "Data", tkt->enc_part2->client->data[i].data, tkt->enc_part2->client->data[i].length);
    }

    print_indent(level+3); printf("Realm: \n");
    if (args.verbose & PRINT_VERBOSE) print_kv_int(level+4, "Magic", tkt->enc_part2->client->realm.magic);
    if (args.verbose & PRINT_VERBOSE) print_kv_int(level+4, "Length", tkt->enc_part2->client->realm.length);
    print_kv_str(level+4, "Data", tkt->enc_part2->client->realm.data, tkt->enc_part2->client->realm.length);

    krb5_authdata** authdata = NULL;
    for (i = 0, authdata = tkt->enc_part2->authorization_data; *authdata != NULL; authdata++, i++) {
        print_indent(level+2); printf("Authorization Data[%d]: \n", i);
        if (args.verbose & PRINT_VERBOSE) print_kv_int(level+3, "Magic", (*authdata)->magic);
        if (args.verbose & PRINT_VERBOSE) print_kv_int(level+3, "Length", (*authdata)->length);
        print_kv_int(level+3, "AD_type", (*authdata)->ad_type);
        print_kv_str(level+3, "Contents", (*authdata)->contents, (*authdata)->length);
    }

    krb5_address** addresses = NULL;
    for (i = 0, addresses = tkt->enc_part2->caddrs; *addresses != NULL; addresses++, i++) {
        print_indent(level+2); printf("CAddrs[%d]: \n", i);
        if (args.verbose & PRINT_VERBOSE) print_kv_int(level+3, "Magic", (*addresses)->magic);
        if (args.verbose & PRINT_VERBOSE) print_kv_int(level+3, "Length", (*addresses)->length);
        print_kv_int(level+3, "AddrType", (*addresses)->addrtype);
        print_kv_str(level+3, "Contents", (*addresses)->contents, (*addresses)->length);
    }

    print_indent(level+2); printf("Session: \n");
    if (args.verbose & PRINT_VERBOSE) print_kv_int(level+3, "Magic", tkt->enc_part2->session->magic);
    if (args.verbose & PRINT_VERBOSE) print_kv_int(level+3, "Length", tkt->enc_part2->session->length);
    print_kv_int(level+3, "Enctype", tkt->enc_part2->session->enctype);
    print_kv_str(level+3, "Contents", tkt->enc_part2->session->contents, tkt->enc_part2->session->length);

    print_indent(level+2); printf("Times: \n");
    print_kv_time(level+3, "AuthTime", tkt->enc_part2->times.authtime);
    print_kv_time(level+3, "EndTime", tkt->enc_part2->times.endtime);
    print_kv_time(level+3, "RenewTill", tkt->enc_part2->times.renew_till);
    print_kv_time(level+3, "StartTime", tkt->enc_part2->times.starttime);

    print_indent(level+2); printf("Transited: \n");
    if (args.verbose & PRINT_VERBOSE) print_kv_int(level+3, "Magic", tkt->enc_part2->transited.magic);
    print_kv_int(level+3, "TrType", tkt->enc_part2->transited.tr_type);
    print_kv_int(level+3, "TrType", tkt->enc_part2->transited.tr_contents.length);
    print_kv_str(level+3, "Contents", tkt->enc_part2->transited.tr_contents.data, tkt->enc_part2->transited.tr_contents.length);
}

void print_krb5_cred(const krb5_context ctx, const krb5_creds* creds, const krb5_ticket* tkt)
{
    int i = 0;
    char* client = NULL;
    char* server = NULL;

    printf("========================================\n");
    printf("Credential Structure\n");

    krb5_unparse_name(ctx, creds->client, &client);
    krb5_unparse_name(ctx, creds->server, &server);

    if (client != NULL) printf("Client: %s\n", client);
    if (server != NULL)
    {
        if (strncmp(server, "krbtgt/", 7) == 0)
            printf("Server: %s\n", server);
        else
            printf("SPN: %s\n", server);
    }
    krb5_free_unparsed_name(ctx, client);
    krb5_free_unparsed_name(ctx, server);
    printf("========================================\n");

    if (args.verbose & PRINT_VERBOSE) print_kv_int(0, "Magic", creds->magic);
    print_kv_int(0, "IsSkey", creds->is_skey);
    print_kv_int(0, "TicketFlags", creds->ticket_flags);

    krb5_authdata** authdata = NULL;
    for (i = 0, authdata = creds->authdata; *authdata != NULL; authdata++, i++)
    {
        print_indent(0); printf("[AuthData[%d]]\n", i);
        if (args.verbose & PRINT_VERBOSE) print_kv_int(2, "Magic", creds->authdata[i]->magic);
        print_kv_int(1, "AdType", creds->authdata[i]->ad_type);
        if (args.verbose & PRINT_VERBOSE) print_kv_int(1, "Length", creds->authdata[i]->length);
        print_kv_str(1, "Contents", creds->authdata[i]->contents, creds->authdata[0]->length);
    }

    krb5_address** addresses = NULL;
    for (i = 0, addresses = creds->addresses; *addresses != NULL; i++, addresses++)
    {
        print_indent(0); printf("[Addresses[%d]]\n", i);
        if (args.verbose & PRINT_VERBOSE) print_kv_int(1, "Magic", creds->addresses[i]->magic);
        print_kv_int(1, "AddrType", creds->addresses[i]->addrtype);
        if (args.verbose & PRINT_VERBOSE) print_kv_int(1, "length", creds->addresses[i]->length);
        print_kv_str(1, "Contents", creds->addresses[i]->contents, creds->addresses[0]->length);
    }

    print_indent(0); printf("\n[Client]\n");
    if (args.verbose & PRINT_VERBOSE) print_kv_int(1, "Magic", creds->client->magic);
    if (args.verbose & PRINT_VERBOSE) print_kv_int(1, "Length", creds->client->length);
    print_kv_int(1, "Type", creds->client->type);

    print_indent(1); printf("Realm:\n");
    if (args.verbose & PRINT_VERBOSE) print_kv_int(2, "Magic", creds->client->realm.magic);
    if (args.verbose & PRINT_VERBOSE) print_kv_int(2, "Length", creds->client->realm.length);
    print_kv_str(2, "Data", creds->client->realm.data, creds->client->realm.length);

    print_indent(1); printf("Data: \n");
    if (args.verbose & PRINT_VERBOSE) print_kv_int(2, "Magic", creds->client->data->magic);
    if (args.verbose & PRINT_VERBOSE) print_kv_int(2, "Length", creds->client->data->length);
    print_kv_str(2, "Data", creds->client->data->data, creds->client->data->length);

    print_indent(0); printf("\n[Server]\n");
    if (args.verbose & PRINT_VERBOSE) print_kv_int(1, "Magic", creds->server->magic);
    if (args.verbose & PRINT_VERBOSE) print_kv_int(1, "Length", creds->server->length);
    print_kv_int(1, "Type", creds->server->type);

    print_indent(1); printf("Realm: \n");
    if (args.verbose & PRINT_VERBOSE) print_kv_int(2, "Magic", creds->server->realm.magic);
    if (args.verbose & PRINT_VERBOSE) print_kv_int(2, "Length", creds->server->realm.length);
    print_kv_str(2, "Data", creds->server->realm.data, creds->server->realm.length);

    for (i=0; i<creds->server->length; i++)
    {
        print_indent(1); printf("Data[%d]: \n", i);
        if (args.verbose & PRINT_VERBOSE) print_kv_int(2, "Magic", creds->server->data[i].magic);
        if (args.verbose & PRINT_VERBOSE) print_kv_int(2, "Length", creds->server->data[i].length);
        print_kv_str(2, "Data", creds->server->data[i].data, creds->server->data[i].length);
    }

    print_indent(0); printf("\n[Times]\n");
    print_kv_time(1, "AuthTime", creds->times.authtime);
    print_kv_time(1, "StartTime", creds->times.starttime);
    print_kv_time(1, "EndTime", creds->times.endtime);
    print_kv_time(1, "RenewTill", creds->times.renew_till);

    print_indent(0); printf("\n[KeyBlock]\n");
    if (args.verbose & PRINT_VERBOSE) print_kv_int(1, "Magic", creds->keyblock.magic);
    if (args.verbose & PRINT_VERBOSE) print_kv_int(1, "Length", creds->keyblock.length);
    print_kv_int(1, "EncType", creds->keyblock.enctype);
    print_kv_bytes(1, "Contents", creds->keyblock.contents, creds->keyblock.length);

    print_indent(0); printf("\n[SecondTicket]\n");
    if (args.verbose & PRINT_VERBOSE) print_kv_int(1, "Magic", creds->second_ticket.magic);
    if (args.verbose & PRINT_VERBOSE) print_kv_int(1, "Length", creds->second_ticket.length);
    print_kv_bytes(1, "Data", creds->second_ticket.data, creds->second_ticket.length);

    if (tkt != NULL)
    {
        print_indent(0); printf("\n[Ticket]\n");
        print_krb5_ticket(0, tkt);
    }
}
