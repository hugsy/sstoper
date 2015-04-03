#!/bin/bash

if [ $# -ne 2 ]; then
    echo "[-] Invalid syntax"
    echo "Syntax: $0 host port"
    exit 1
fi

echo "" | openssl s_client -tls1 -showcerts -connect $1:$2 2>/dev/null | sed -n -e '/BEGIN\ CERTIFICATE/,/END\ CERTIFICATE/ p' > $1-$2.crt
echo "[+] Certificate written to '$1-$2.crt'"
exit 0
