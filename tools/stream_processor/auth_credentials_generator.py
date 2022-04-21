#!/usr/bin/python

import hashlib
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--credentials-pair", nargs="+",
                    action='append', default=[])
args = parser.parse_args()


def generate_credentials(cred):
    m = hashlib.sha512()
    username, password = cred.split(":")
    m.update(b"%s" % (password.encode()))
    passwordhex = m.hexdigest()
    print("""[AUTH]
    user %s
    password %s
""" % (username, passwordhex))


for cred_pair in args.credentials_pair:
    for cred in cred_pair:
        generate_credentials(cred)
