#include <stdio.h>
#include <krb5.h>
#include <time.h>
#include <string.h>

#include "printing.h"
#include "types.h"

void print_kv_time(const int level, const char *label, const long value)
{
    char buf[32] = {0};
    struct tm *tm_info = NULL;
    if ((tm_info = localtime(&value)) != NULL)
    {
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm_info);
        print_kv_str(level, label, buf, strlen(buf));
    }
    else
        print_kv_int(level, label, value);
}

void print_hashcat_format(const int enctype, char* username, char* realm, char* service, const unsigned char* enc_part, const size_t enc_part_len) {
    if (enctype == ENCTYPE_AES256_CTS_HMAC_SHA1_96 || enctype == ENCTYPE_AES128_CTS_HMAC_SHA1_96)
        printf("$krb5tgs$%d$%s$%s$", enctype, username, realm);
    else if (enctype == ENCTYPE_ARCFOUR_HMAC )
        printf("$krb5tgs$%d$*%s$%s$%s/%s*$", enctype, username, realm, service, username);

    size_t i;
    for (i = 0; i < enc_part_len; i++)
    {
        if ( (enctype == ENCTYPE_AES256_CTS_HMAC_SHA1_96 || enctype == ENCTYPE_AES128_CTS_HMAC_SHA1_96) && i == 12) putchar('$');
        if ( enctype == ENCTYPE_ARCFOUR_HMAC && i == 16) putchar('$');
        printf("%02x", enc_part[i]&0xff);
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

static void print_kv_bytes(const int level, const char *label, const unsigned char* value, unsigned int value_len)
{
    print_indent(level);
    printf("%s: ", label);
    unsigned int i = 0;
    for (i = 0; i < value_len; i++) printf("%02x", value[i]&0xff);
    putchar('\n');
}

void print_krb5_ticket(const int level, const krb5_ticket* tkt, const args_t* args)
{
    int i;

    print_kv_int(level+1, "Magic", tkt->magic);

    print_indent(level+1); printf("Server: \n");
    print_kv_int(level+2, "Magic", tkt->server->magic);
    print_kv_int(level+2, "Length", tkt->server->length);
    print_kv_int(level+2, "Type", tkt->server->type);

    print_indent(level+2); printf("Realm: \n");
    print_kv_int(level+3, "Magic", tkt->server->realm.magic);
    print_kv_int(level+3, "Length", tkt->server->realm.length);
    print_kv_str(level+3, "Data", tkt->server->realm.data, tkt->server->realm.length);

    for (i = 0; i < tkt->server->length; i++) {
        print_indent(level+2); printf("Data[%d]: \n", i);
        print_kv_int(level+3, "Magic", tkt->server->data[i].magic);
        print_kv_int(level+3, "Length", tkt->server->data[i].length);
        print_kv_str(level+3, "Data", tkt->server->data[i].data, tkt->server->data[i].length);
    }

    print_indent(level+1); printf("Enc_part: \n");
    print_kv_int(level+2, "Magic", tkt->enc_part.magic);
    print_kv_int(level+2, "Enctype", tkt->enc_part.enctype);
    print_kv_int(level+2, "Kvno", tkt->enc_part.kvno);

    print_indent(level+2); printf("Ciphertext: \n");
    print_kv_int(level+3, "Magic", tkt->enc_part.ciphertext.magic);
    print_kv_int(level+3, "Length", tkt->enc_part.ciphertext.length);
    print_kv_bytes(level+3, "Data", tkt->enc_part.ciphertext.data, tkt->enc_part.ciphertext.length);


    if (tkt->enc_part2 == NULL) {
        print_indent(level+1); printf("Enc_part2: (nil)\n");
        goto after_enc_part2;
    }

    print_indent(level+1); printf("Enc_part2: \n");
    print_kv_int(level+2, "Magic", tkt->enc_part2->magic);
    print_kv_int(level+2, "Flags", tkt->enc_part2->flags);

    print_indent(level+2); printf("Client: \n");
    print_kv_int(level+3, "Magic", tkt->enc_part2->client->magic);
    print_kv_int(level+3, "Type", tkt->enc_part2->client->type);
    print_kv_int(level+3, "Length", tkt->enc_part2->client->length);

    for (i = 0; i < tkt->enc_part2->client->length; i++) {
        print_indent(level+3); printf("Data[%d]: \n", i);
        print_kv_int(level+4, "Magic", tkt->enc_part2->client->data[i].magic);
        print_kv_int(level+4, "Length", tkt->enc_part2->client->data[i].length);
        print_kv_str(level+4, "Data", tkt->enc_part2->client->data[i].data, tkt->enc_part2->client->data[i].length);
    }

    print_indent(level+3); printf("Realm: \n");
    print_kv_int(level+4, "Magic", tkt->enc_part2->client->realm.magic);
    print_kv_int(level+4, "Length", tkt->enc_part2->client->realm.length);
    print_kv_str(level+4, "Data", tkt->enc_part2->client->realm.data, tkt->enc_part2->client->realm.length);

    krb5_authdata** authdata = NULL;
    for (i = 0, authdata = tkt->enc_part2->authorization_data; *authdata != NULL; authdata++, i++) {
        print_indent(level+2); printf("Authorization Data[%d]: \n", i);
        print_kv_int(level+3, "Magic", (*authdata)->magic);
        print_kv_int(level+3, "AD_type", (*authdata)->ad_type);
        print_kv_int(level+3, "Length", (*authdata)->length);
        print_kv_str(level+3, "Contents", (*authdata)->contents, (*authdata)->length);
    }

    krb5_address** addresses = NULL;
    for (i = 0, addresses = tkt->enc_part2->caddrs; *addresses != NULL; addresses++, i++) {
        print_indent(level+2); printf("CAddrs[%d]: \n", i);
        print_kv_int(level+3, "Magic", (*addresses)->magic);
        print_kv_int(level+3, "AddrType", (*addresses)->addrtype);
        print_kv_int(level+3, "Length", (*addresses)->length);
        print_kv_str(level+3, "Contents", (*addresses)->contents, (*addresses)->length);
    }

    print_indent(level+2); printf("Session: \n");
    print_kv_int(level+3, "Magic", tkt->enc_part2->session->magic);
    print_kv_int(level+3, "Enctype", tkt->enc_part2->session->enctype);
    print_kv_int(level+3, "Length", tkt->enc_part2->session->length);
    print_kv_str(level+3, "Contents", tkt->enc_part2->session->contents, tkt->enc_part2->session->length);

    print_indent(level+2); printf("Times: \n");
    print_kv_time(level+3, "AuthTime", tkt->enc_part2->times.authtime);
    print_kv_time(level+3, "EndTime", tkt->enc_part2->times.endtime);
    print_kv_time(level+3, "RenewTill", tkt->enc_part2->times.renew_till);
    print_kv_time(level+3, "StartTime", tkt->enc_part2->times.starttime);

    print_indent(level+2); printf("Transited: \n");
    print_kv_int(level+3, "Magic", tkt->enc_part2->transited.magic);
    print_kv_int(level+3, "TrType", tkt->enc_part2->transited.tr_type);
    print_kv_int(level+3, "TrType", tkt->enc_part2->transited.tr_contents.length);
    print_kv_str(level+3, "Contents", tkt->enc_part2->transited.tr_contents.data, tkt->enc_part2->transited.tr_contents.length);

after_enc_part2:
    if (args->hashcat)
    {
        char* username = tkt->server->data[0].data;
        username[tkt->server->data[0].length] = '\0';
        // char* service = tkt->server->data[0].data;
        // service[tkt->server->data[0].length] = '\0';
        char* realm = tkt->server->realm.data;
        realm[tkt->server->realm.length] = '\0';

        print_indent(level+1); printf("Hashcat format: ");
        print_hashcat_format(
            tkt->enc_part.enctype,
            username,
            realm,
            username,
            tkt->enc_part.ciphertext.data,
            tkt->enc_part.ciphertext.length
        );
    }
}

void print_krb5_cred(const krb5_creds* creds, const krb5_ticket* tkt, const args_t* args)
{
    int i = 0;
    printf("----------------------------------------\n");

    printf("Credential Structure: \n");
    print_kv_int(1, "Magic", creds->magic);
    print_kv_int(1, "IsSkey", creds->is_skey);
    print_kv_int(1, "TicketFlags", creds->ticket_flags);

    krb5_authdata** authdata = NULL;
    for (i = 0, authdata = creds->authdata; *authdata != NULL; authdata++, i++)
    {
        print_indent(1); printf("AuthData[%d]: \n", i);
        print_kv_int(2, "Magic", creds->authdata[i]->magic);
        print_kv_int(2, "AdType", creds->authdata[i]->ad_type);
        print_kv_int(2, "Length", creds->authdata[i]->length);
        print_kv_str(2, "Contents", creds->authdata[i]->contents, creds->authdata[0]->length);
    }

    krb5_address** addresses = NULL;
    for (i = 0, addresses = creds->addresses; *addresses != NULL; i++, addresses++)
    {
        print_indent(1); printf("Addresses[%d]: \n", i);
        print_kv_int(2, "Magic", creds->addresses[i]->magic);
        print_kv_int(2, "AddrType", creds->addresses[i]->addrtype);
        print_kv_int(2, "length", creds->addresses[i]->length);
        print_kv_str(2, "Contents", creds->addresses[i]->contents, creds->addresses[0]->length);
    }

    print_indent(1); printf("Client: \n");
    print_kv_int(2, "Magic", creds->client->magic);
    print_kv_int(2, "Length", creds->client->length);
    print_kv_int(2, "Type", creds->client->type);

    print_indent(2); printf("Realm: \n");
    print_kv_int(3, "Magic", creds->client->realm.magic);
    print_kv_int(3, "Length", creds->client->realm.length);
    print_kv_str(3, "Data", creds->client->realm.data, creds->client->realm.length);

    print_indent(2); printf("Data: \n");
    print_kv_int(3, "Magic", creds->client->data->magic);
    print_kv_int(3, "Length", creds->client->data->length);
    print_kv_str(3, "Data", creds->client->data->data, creds->client->data->length);

    print_indent(1); printf("Server: \n");
    print_kv_int(2, "Magic", creds->server->magic);
    print_kv_int(2, "Length", creds->server->length);
    print_kv_int(2, "Type", creds->server->type);

    print_indent(2); printf("Realm: \n");
    print_kv_int(3, "Magic", creds->server->realm.magic);
    print_kv_int(3, "Length", creds->server->realm.length);
    print_kv_str(3, "Data", creds->server->realm.data, creds->server->realm.length);

    print_indent(2); printf("Data: \n");
    print_kv_int(3, "Magic", creds->server->data->magic);
    print_kv_int(3, "Length", creds->server->data->length);
    print_kv_str(3, "Data", creds->server->data->data, creds->server->data->length);


    print_indent(1); printf("Times: \n");
    print_kv_time(2, "AuthTime", creds->times.authtime);
    print_kv_time(2, "StartTime", creds->times.starttime);
    print_kv_time(2, "EndTime", creds->times.endtime);
    print_kv_time(2, "RenewTill", creds->times.renew_till);

    print_indent(1); printf("KeyBlock: \n");
    print_kv_int(2, "Magic", creds->keyblock.magic);
    print_kv_int(2, "EncType", creds->keyblock.enctype);
    print_kv_int(2, "length", creds->keyblock.length);
    print_kv_bytes(2, "Contents", creds->keyblock.contents, creds->keyblock.length);

    print_indent(1); printf("SecondTicket: \n");
    print_kv_int(2, "Magic", creds->second_ticket.magic);
    print_kv_int(2, "Length", creds->second_ticket.length);
    print_kv_bytes(2, "Data", creds->second_ticket.data, creds->second_ticket.length);

    if (tkt != NULL)
    {
        print_indent(1); printf("Ticket: \n");
        print_krb5_ticket(1, tkt, args);
    }
}
