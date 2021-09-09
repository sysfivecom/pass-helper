#!/usr/bin/env python3

## pass-helper
## Copyright © 2021 sysfive.com GmbH
##
## GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Add or update a key in one or more password stores

Keys always need to be specified by their unique KEY ID
(e.g EE3F9BAB64010DC0) as there is no possibility to guess them
in a secure manner (e.g. you have several keys for the same
UID, think of Jenkins or old keys etc.).
When a key exists already and the subkeys are the same,
no reencryption will be triggered.
There are safety checks before adding a pubkey to a store and
there will be performed checks after adding the key.
If all checks are successful, a commit will be prepared.
If requested, the commit will be pushed to Gerrit for one
or multiple reviewers.
Password stores are given by their top directory.
If no directory name is given, use the working directory.

Examples:
%(prog)s -r ajutzy -r sheykes EE3F9BAB64010DC0 ssfn-pass geco-pass
  Put pubkey EE3F9BAB64010DC0 into password stores in directories
  ssfn-pass, geco-pass, re-encrypt and push to Gerrit for reviewers
  ajutzy and sheykes.

It's also possible to use the globbing of the shell:
%(prog)s EE3F9BAB64010DC0 ../*-pass
  Add pubkey EE3F9BAB64010DC0 to all password stores in directories
  ../*-pass
"""

import argparse
import getpass
import logging
from pathlib import Path
import os
import subprocess
import sys
from typing import List, Set, Tuple

from check_secrets import Passwordstore
import gpg_helpers


def parse() -> argparse.Namespace:
    """Parse arguments from Commandline"""
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        description="Add or replace a GPG key in one or more password stores.",
    )
    parser.add_argument(
        "key_id",
        type=str,
        help=(
            "GPG KEY ID that should be added, e.g. EE3F9BAB64010DC0.\n"
            "This ID cannot be determined reliably so must be provided."
        ),
    )
    parser.add_argument(
        "directories",
        default=".",
        nargs=argparse.REMAINDER,
        help="Directories of password stores",
    )
    parser.add_argument(
        "-u",
        "--uid",
        type=str,
        help="USER ID (email address) to be added, defaults to <username>@sysfive.com\n"
        "Username is the name of the user calling the script.",
    )
    parser.add_argument(
        "-c",
        "--continue-on-errors",
        action="store_true",
        help="Continue on errors in a store.",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-d", "--debug", action="store_true")
    parser.add_argument(
        "-e",
        "--encrypt-always",
        action="store_true",
        default=False,
        help=(
            "Trigger encryption even when just updating a key.\n"
            "This should fix errors with encrypted files."
        ),
    )
    parser.add_argument(
        "-r",
        "--reviewers",
        type=str,
        action="append",
        help="Commit changes to Gerrit for reviewer <reviewer_name>.",
    )
    return parser.parse_args()


def is_uid_in_key_uids(uid: str, fingerprint: str) -> bool:
    """Check whether the uid (email) is attached to the key with ID key_id"""
    uids = gpg_helpers.get_user_ids_from_fingerprint(fingerprint)
    return uid in uids


def git_review(base_dir: Path, reviewers: List[str]) -> bool:
    """Send the commit to Gerrit reviewers

    Return success as bool
    """

    args = ["git-review", f"--reviewers={','.join(reviewers)}"]
    env = {
        "LANG": "C",
        "PATH": os.environ["PATH"],
    }
    try:
        pass_result = subprocess.run(
            args,
            env=env,
            cwd=base_dir,
            capture_output=True,
            encoding="utf8",
            check=True,
            timeout=60,
        )
        logging.debug(pass_result.stdout)
        logging.debug(pass_result.stderr)
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"Git-review not successful for {base_dir}!")
        logging.exception(e)
        logging.error(e.stdout)
        logging.error(e.stderr)
        return False


def check_uid_keyid(uid: str, key_id: str) -> bool:
    """Perform logical checks on given UID (email) and KEY ID (hexdigits)"""
    if "@" not in uid:
        logging.error("UID must contain an email address")
        return False
    if not gpg_helpers.KEY_ID_PATTERN.match(key_id):
        logging.error("KEY ID must be the hexadecimal KEY ID (at least 16 digits)")
        return False
    return True


def get_fingerprint(key_id: str) -> str:
    """Call gpg --fingerprint KEY_ID"""
    gpg_fingerprint = ""
    try:
        gpg_fingerprint = gpg_helpers.get_gpg_fingerprint(key_id)
    except subprocess.CalledProcessError as e:
        logging.error("Could not get fingerprint for key!")
        logging.error(e)
    return gpg_fingerprint


def add_key_to_store(
    base_dir: Path,
    uid: str,
    key_ids: List[str],
    pubkey_ascii: str,
    reviewers: List[str],
    encrypt_always: bool,
) -> Tuple[bool, List[str]]:
    """Add the key to the store

    Requires a valid password store.
    - Add key
    - Check store for errors
    - If reviewers, submit to Gerrit
    After every sub action check eror state and return if errors
    """
    errors: List[str] = []
    # Ensure a working pass store
    pass_store = Passwordstore.create_valid_store(base_dir)
    if pass_store is None:
        logging.error("Pass store could not be validated!")
        return False, errors

    # Always fail on first brokenly encrypted file
    # Checking further files only costs time
    fail_on_first_file = True
    success, errors = pass_store.add_key_to_store(
        uid, key_ids, pubkey_ascii, encrypt_always, fail_on_first_file
    )
    if success:
        logging.info(f"OK: Added key to Password Store {base_dir}.")
    else:
        logging.error(f"Adding key to Password Store {base_dir} not successful!")
        return False, errors

    if reviewers:
        success = git_review(pass_store.secrets_path, reviewers)
        if success:
            logging.info("Submitted changes to Gerrit.")
        else:
            logging.error("Submitting of changes to Gerrit failed!")
    return success, errors


def main(args: argparse.Namespace) -> None:
    """Check parameters for consistency and process every store

    Key id is mandatory, checked in parse()
    If there are errors in a store, continue only when
    continue_on_errors is set.
    """
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        if args.verbose:
            logging.basicConfig(level=logging.INFO)

    logging.debug(f"raw args: {args}")
    user_name = getpass.getuser()
    # Default mail address to username@sysfive.com
    if args.uid:
        uid = args.uid
    else:
        uid = f"{user_name}@sysfive.com"
    reviewers = []
    if args.reviewers:
        for entry in args.reviewers:
            for part in entry.split(","):
                reviewers.append(part)
    key_id = args.key_id
    directories = args.directories
    continue_on_errors = args.continue_on_errors
    encrypt_always = args.encrypt_always
    logging.debug(
        f"UID: {uid}, Key_ID: {key_id}, continue_on_errors: {continue_on_errors}, encrypt_always: {encrypt_always}"
    )
    logging.debug(f"reviewers: {reviewers}, directories: {directories}")

    if not check_uid_keyid(uid, key_id):
        sys.exit(2)
    gpg_fingerprint = get_fingerprint(key_id)
    if not is_uid_in_key_uids(uid, gpg_fingerprint):
        logging.error(
            f"You requested <{uid}> but it's not in the fingerprint for KEY {key_id}!"
        )
        sys.exit(2)
    key_ids = gpg_helpers.get_ids_from_fingerprint(gpg_fingerprint)
    pub_id = key_ids[0]
    if pub_id == "":
        logging.error(f"Could not find key id {key_id} in fingerprint of key {key_id}")
        logging.error("Check for gpg errors.")
        sys.exit(2)
    if pub_id != key_id:
        logging.warning(
            f"Replaced ID {key_id} with pub key ID {pub_id} to ensure unambiguity."
        )

    pubkey = gpg_helpers.export_gpg_pubkey(pub_id)

    stores_successful: List[str] = []
    stores_errors: List[str] = []
    for dir_name in directories:
        success, messages = add_key_to_store(
            base_dir=Path(dir_name),
            uid=uid,
            key_ids=key_ids,
            pubkey_ascii=pubkey,
            reviewers=reviewers,
            encrypt_always=encrypt_always,
        )
        if success:
            stores_successful.append(dir_name)
        else:
            stores_errors.append(dir_name)
            for message in messages:
                print(message)
        if not success and not continue_on_errors:
            # Print stats on end
            print(f"Stores successful: {', '.join(stores_successful)}")
            print(f"Stores with errors: {', '.join(stores_errors)}")
            logging.error("Aborting on errors in store")
            sys.exit(2)

    # Print stats on end
    print(f"Stores successful: {', '.join(stores_successful)}")
    print(f"Stores with errors: {', '.join(stores_errors)}")


if __name__ == "__main__":
    main(parse())
