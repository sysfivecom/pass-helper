#!/usr/bin/env python3

## pass-helper
## Copyright © 2021 sysfive.com GmbH
##
## GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""GPG helper functions used in different commands

"""
import logging
from pathlib import Path
import os
import re
import subprocess
from typing import List
from config import GPG_OPTS

# GPG --with-colons format explained:
# https://git.gnupg.org/cgi-bin/gitweb.cgi?p=gnupg.git;a=blob_plain;f=doc/DETAILS
# See also get_ids_from_fingerprint() for an example

# Match hexadecimal number with 16 to 40 digits
KEY_ID_PATTERN = re.compile("([0-9a-fA-F]{16,40})$")
# Pattern for gpg --fingerprint --with-colons
# Match uid <someone@example.com> and catch only someone@example.com
# Don't match revoked uids (uid:r)
USER_ID_PATTERN = re.compile("(?:uid:[^r].*<)(.*)(?:>)")
# Public key pattern from gpg --fingerprint --with-colons
PUBKEY_PATTERN = re.compile("(?:pub:[^:]*:[^:]*:[^:]*:)(?P<pubkey>[^:]*)(?::)")
# Subkey pattern from gpg --fingerprint --with-colons
SUBKEY_PATTERN = re.compile("(?:sub:[^:]*:[^:]*:[^:]*:)(?P<subkey>[^:]*)(?::)")
# Output is:
# gpg: key KEYID: ...
REAL_ID_PATTERN = re.compile("(?:gpg: key )(?P<key_id>[0-9a-fA-F]{16,40})(?::)")
# Expired keys start with pub:e, catch only date field #7
EXPIRE_PATTERN = re.compile(
    "(?:pub:e:[^:]*:[^:]*:[^:]*:[^:]*:)(?P<expiration>[^:]*)(?::)"
)
# gpg output for decrypting files shows the IDs encrypted to:
# gpg: encrypted with 3072-bit RSA key, ID EDB209BBBD162994, created 2019-12-19
#      "Jenkins User (Key fuer den Jenkins user) <jenkins@sysfive.com>"
ENCRYPTED_TO_PATTERN = re.compile(r"(?<=, ID )\w+")


def find_bad_gpg_ids(id_file_path: Path) -> List[str]:
    """Return entries which are no key ids

    Filter out lines in the .gpg-id file which
    are not hexadecimal numbers and so are no key ids
    or which are too short or too long (16-40 hexdigits).
    """
    bad_lines = []

    with open(id_file_path, "r") as id_file:
        for line in id_file:
            if not KEY_ID_PATTERN.match(line):
                bad_lines.append(line)
    return bad_lines


def export_gpg_pubkey(key_id: str) -> str:
    """Export the minimal pubkey ascii-enarmored

    Only export the most minimal pubkey possible so it doesn't
    change upon new signatures etc.

    Can raise subprocess.CalledProcessError
    """
    args = ["gpg"]
    args += ["--export-options", "export-minimal", "--export", "--armor"]
    args += GPG_OPTS
    args += [key_id]
    env = {
        "LANG": "C",
        "PATH": os.environ["PATH"],
    }
    logging.debug(args)
    logging.debug(env)
    try:
        gpg_export = subprocess.run(
            args, env=env, capture_output=True, encoding="utf8", check=True
        )
        logging.debug(f"gpg_export.stderr: {gpg_export.stderr}")
    except subprocess.CalledProcessError as e:
        logging.debug(e.stdout)
        logging.debug(e.stderr)
        # This is only to show which exception can be raised
        raise
    return gpg_export.stdout


def get_gpg_fingerprint(key_id: str, gpg_opts: List[str] = GPG_OPTS) -> str:
    """Run gpg --fingerprint --with-colons KEY_ID

    Can raise subprocess.CalledProcessError
    """
    args = ["gpg"]
    args += ["--fingerprint", "--with-colons"]
    args += gpg_opts
    args += [key_id]
    env = {
        "LANG": "C",
        "PATH": os.environ["PATH"],
    }
    try:
        gpg_fingerprint = subprocess.run(
            args, env=env, capture_output=True, encoding="utf8", check=True
        )
        logging.debug(gpg_fingerprint.stdout)
        logging.debug(gpg_fingerprint.stderr)
    except subprocess.CalledProcessError as e:
        logging.debug(e.stdout)
        logging.debug(e.stderr)
        raise
    return gpg_fingerprint.stdout


def get_user_ids_from_fingerprint(gpg_fingerprint: str) -> List[str]:
    """Return uids for given key id from gpg

    Every gpg key has at least one uid attached to it.
    Return the list of uids.
    """
    user_ids = USER_ID_PATTERN.findall(gpg_fingerprint)
    return user_ids


def get_ids_from_fingerprint(gpg_fingerprint: str) -> List[str]:
    """Get key IDs of public key and its subkey(s)


    Input:

    tru::7:1536935799:1570801449
    pub:u:4096:1:B003FCB95ACB6D9D:1507728986:1570801449::u:::scESC::::::23::0:
    fpr:::::::::B953F278DE1B3ECFCF14C285B003FCB95ACB6D9D:
    uid:u::::1507730022::5BF2C35537DF54ACEF50E480A5A4361061EEC476::Michael Kesper <mkesper@sysfive.com>::::::::::0:
    uid:u::::1507729449::A26B0BB90662D71FE2A71BF39C79DC82D5125CD9::Michael Kesper <mkesper@sysfive.de>::::::::::0:
    sub:u:4096:1:E655A59A154DF0F0:1507728986::::::e::::::23:
    fpr:::::::::4CE3A24A700EB057CE168D1DE655A59A154DF0F0:

    Output:
    ["B003FCB95ACB6D9D", "E655A59A154DF0F0"]
    """
    ids = []
    pubkey_match = PUBKEY_PATTERN.search(gpg_fingerprint)
    if pubkey_match is None:
        logging.error("Unable to match pubkey pattern!")
    else:
        ids.append(pubkey_match.group("pubkey"))

    subkey_match = SUBKEY_PATTERN.findall(gpg_fingerprint)
    if subkey_match is None:
        logging.error("Unable to match subkeys!")
    else:
        ids += subkey_match
    return ids


if __name__ == "__main__":
    print("This is just a helper.")
