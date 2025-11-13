# kdump

Tool to dump info from Kerberos Tickets.

## Usage

```bash
$ kdump -h
Usage: kdump [-h] [-c] [-v] [-H]
	-h help menu
	-c specifies credential cache
	-v verbose
	-H prints encrypted part of TGS in hashcat format
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