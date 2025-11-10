#pragma once

#include "types.h"

static void print_hashcat_format(const int enctype, char* username, char* realm, char* service, const unsigned char* enc_part, const size_t enc_part_len);
static void print_indent(const int level);
static void print_kv_int(const level, const char *label, const long value);
static void print_kv_str(const int level, const char *label, const char* value, const unsigned int value_len);
static void print_kv_bytes(const int level, const char *label, const unsigned char* value, const unsigned int value_len);
static void print_kv_time(const int level, const char *label, const long value);
static void print_krb5_ticket(const int level, const krb5_ticket* tkt, const args_t* args);
void print_krb5_cred(const krb5_creds* creds, const krb5_ticket* tkt, const args_t* args);
