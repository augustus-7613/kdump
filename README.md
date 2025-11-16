# kdump

Tool to dump info from Kerberos Tickets.

## Usage

```bash
$ kdump -h
Usage: kdump [-h] [-c] [-v] [-m] [-H]
	-h Help menu
	-c Specifies credential cache
	-v Verbose
	-m Expand magic number. Needs -v
	-p Password used to decrypt the encrypted part of TGS ticket
	-n NTLM hash used to decrypt the encrypted part of TGS ticket
	-H Prints encrypted part of TGS ticket in hashcat format
```

## Build
```
mkdir build
cd build
cmake ..
make
```

## Install
Available on [AUR](https://aur.archlinux.org/packages/kdump)
```
yay -S kdump
```

## Examples
Default usage
```sh
$ kdump -c ccache.arcfour
========================================
Credential Structure
Client: steve.stevenson@CORP.LOCAL
SPN: HTTP/dc01.corp.local@CORP.LOCAL
========================================
IsSkey: 0
TicketFlags: 14745600 ( TKT_FLG_RENEWABLE  TKT_FLG_INITIAL  TKT_FLG_PRE_AUTH )

[Client]
    Type: 1
    Realm:
        Data: CORP.LOCAL
    Data:
        Data: steve.stevenson

[Server]
    Type: 1
    Realm:
        Data: CORP.LOCAL
    Data[0]:
        Data: HTTP
    Data[1]:
        Data: dc01.corp.local

[Times]
    AuthTime: 2025-11-13T17:03:14Z
    StartTime: 2025-11-13T17:03:14Z
    EndTime: 2025-11-14T03:03:14Z
    RenewTill: 2025-11-14T17:03:09Z

[KeyBlock]
    EncType: 23 (arcfour-hmac)
    Contents: cd04c69f9c3bbf066844f7a81fd4ef36

[SecondTicket]
    Data: (nil)

[Ticket]
    Server:
        Type: 1
        Realm:
            Data: CORP.LOCAL
        Data[0]:
            Data: HTTP
        Data[1]:
            Data: dc01.corp.local
    Enc_part:
        Enctype: 23 (arcfour-hmac)
        Kvno: 4
        Ciphertext:
            Data: c4c559e05627b96d35126603bdbb40bfd95af8d37df405e041172758dbdb071b520ad9594e0a53839746e189b1a1c47893af15b5dfa5af9034646d6b1b7aec4cc8... (truncated)
    Enc_part2: (nil)
```

Decrypt `enc_part2` with password of the service account
```sh
$ kdump -c ccache.arcfour -p 'Password1234'
========================================
Credential Structure
Client: steve.stevenson@CORP.LOCAL
SPN: HTTP/dc01.corp.local@CORP.LOCAL
========================================
IsSkey: 0
TicketFlags: 14745600 ( TKT_FLG_RENEWABLE  TKT_FLG_INITIAL  TKT_FLG_PRE_AUTH )

[Client]
    Type: 1
    Realm:
        Data: CORP.LOCAL
    Data:
        Data: steve.stevenson

[Server]
    Type: 1
    Realm:
        Data: CORP.LOCAL
    Data[0]:
        Data: HTTP
    Data[1]:
        Data: dc01.corp.local

[Times]
    AuthTime: 2025-11-13T17:03:14Z
    StartTime: 2025-11-13T17:03:14Z
    EndTime: 2025-11-14T03:03:14Z
    RenewTill: 2025-11-14T17:03:09Z

[KeyBlock]
    EncType: 23 (arcfour-hmac)
    Contents: cd04c69f9c3bbf066844f7a81fd4ef36

[SecondTicket]
    Data: (nil)

[Ticket]
    Server:
        Type: 1
        Realm:
            Data: CORP.LOCAL
        Data[0]:
            Data: HTTP
        Data[1]:
            Data: dc01.corp.local
    Enc_part:
        Enctype: 23 (arcfour-hmac)
        Kvno: 4
        Ciphertext:
            Data: c4c559e05627b96d35126603bdbb40bfd95af8d37df405e041172758dbdb071b520ad9594e0a53839746e189b1a1c47893af15b5dfa5af9034646d6b1b7aec4cc8... (truncated)
    Enc_part2:
        Flags: 14745600
        Client:
            Type: 1
            Data[0]:
                Data: steve.stevenson
            Realm:
                Data: CORP.LOCAL
        Authorization Data[0]:
            AD_type: 1
            Contents: 308203423082033ea00402020080a182033404820330050000000000000001000000e001000058000000000000000a0000002800000038020000000000000c0000... (truncated)
        Session:
            Enctype: 23 (arcfour-hmac)
            Contents: cd04c69f9c3bbf066844f7a81fd4ef36
        Times:
            AuthTime: 2025-11-13T17:03:14Z
            EndTime: 2025-11-14T03:03:14Z
            RenewTill: 2025-11-14T17:03:09Z
            StartTime: 2025-11-13T17:03:14Z
        Transited:
            TrType: 0
            TrType: 0
            Contents: (nil)
```

Output `enc_part2` in Hashcat format
```
$ kdump -c ccache.arcfour -H
========================================
Credential Structure
Client: steve.stevenson@CORP.LOCAL
SPN: HTTP/dc01.corp.local@CORP.LOCAL
========================================
IsSkey: 0
TicketFlags: 14745600 ( TKT_FLG_RENEWABLE  TKT_FLG_INITIAL  TKT_FLG_PRE_AUTH )

[Client]
    Type: 1
    Realm:
        Data: CORP.LOCAL
    Data:
        Data: steve.stevenson

[Server]
    Type: 1
    Realm:
        Data: CORP.LOCAL
    Data[0]:
        Data: HTTP
    Data[1]:
        Data: dc01.corp.local

[Times]
    AuthTime: 2025-11-13T17:03:14Z
    StartTime: 2025-11-13T17:03:14Z
    EndTime: 2025-11-14T03:03:14Z
    RenewTill: 2025-11-14T17:03:09Z

[KeyBlock]
    EncType: 23 (arcfour-hmac)
    Contents: cd04c69f9c3bbf066844f7a81fd4ef36

[SecondTicket]
    Data: (nil)

[Ticket]
    Server:
        Type: 1
        Realm:
            Data: CORP.LOCAL
        Data[0]:
            Data: HTTP
        Data[1]:
            Data: dc01.corp.local
    Enc_part:
        Enctype: 23 (arcfour-hmac)
        Kvno: 4
        Ciphertext:
            Data: c4c559e05627b96d35126603bdbb40bfd95af8d37df405e041172758dbdb071b520ad9594e0a53839746e189b1a1c47893af15b5dfa5af9034646d6b1b7aec4cc8... (truncated)
            Hashcat format: $krb5tgs$23$*<SVC-USERNAME>$CORP.LOCAL$HTTP/dc01.corp.local*$c4c559e05627b96d35126603bdbb40bf$d95af8d37df405e041172758dbdb071b520ad9594e0a53839746e189b1a1c47893af15b5dfa5af9034646d6b1b7aec4cc80394aa7f2570deed400ef54d91f97fedb3bc26e962491846c6cbe33ddb04646aea86d63767ae40582ec99f575193c7c128e54c4fa4e7fc32f73f79a4baebf5c4e568078513cd8e5a07d3e6f1709fdadd2a72bce2de73668086fa304f764a9fff7b0bae75aa7c7b570a5a6744def4abacea4068f4d1f2176a35f78d3c103a42ca6f5611c7a8b3f58476e8820705779b782528c7d279d8b99019aa598505a3987f6235a7a3dcda38cdd525b2c881b8d69f1f045de15b5b3a1a3feed85a29d320c59b21857e0677dda3294e0ad4180a86577bd9c9e48cabde803a0d249574317adedacde7407c18da71c9b5ad179016b39158f9115c5235fa36343a8e01b5f2873871715996323a1b66c86d243fee115428e4bbec5b7b1ca680219318c03f83d7f6924769168bb7a98737decab96791d248fd12cc2daaec445fdd7823508a3e159d6dafc9fe131b65154a89f396c208b72f64fc8ed2d10cc94818043815b6b85d56607af77e84d004edae32a24e26e7f3643b1983c659641e35ed024888d87526197dc5a5b3a051a97a712c06e5ac8a3dc266eeb476e5b270606e139f7e62cc9ed86f759ea12552e9975f24fd90e48f229fc299ef8cff432ea5e9d6c9065d949be3a3122fac0843d9290e6c3d462667521741b16ff8dc1a80f7431f2b1a1ba38e9d8d39bf4f1bd2a5072875d7f509ccce01795fb13c75836e7fb6fb40c9b2202cb607cb32373ce6371af0f71d3a01ef88fc1aa86bc10ccd7717cadd2524b6b1e3118e0baffa94dc56611ca3f5b71713bc305dcec2b00f8a3509d685eea6cc8d17e8dd53f21167cc7f1c707ddb84eec33dfb487eb0896e52092add7bf8a92977d59f04ff6517bdf9e6139f5b67c5e34ec6f3ba8342d3f40173485898cb98f9ce09fa3eeca7f91642a3c03f9fd1edc271ff03896086dbc190421f8f05118ac14e656a85389ff8f33c0bd0f07acab2ce83f7bda510b89f47a07134a834dd87b4629ebbfcb9398d65b3867731b73f3ce9cfcd1563b43c42ea3e2410161f4f0aa09b989531d06321adc180a506f037509b9d32638f8fecfe5736415807b934a38a49cd6bf0f015675284cfbed93d776ee40c5034f652a0b62a4e93d0fd0f2c342e42cdde4acdfc8bb1460c14e81b23cbe0c0ebe360fb31ab4172f6cf1551077f398b70624fa108a28708cf936796286678ea08e8ee73562ed63c5d480fdcdff7de71ee966b5bd70f7402c84d8e847f75d7c783a5cbe25aa58c856ddbbc0c97dc45775c0ad4cc97db38b39dd4cc2f92fd3965e854b80dcd7ebcafaf5018780ee1d7a0d362bd8892fe820ce9049fc83746dcfea6a582b0e03b938c1c5eb11eae11e9167e1c8975281d46d65cde0d24f061ab7bd8b88cecacf2d8394040215c5511cc3a9060ea3fb3d94a30195a63
    Enc_part2: (nil)
```