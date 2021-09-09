#!/usr/bin/env python3

## pass-helper
## Copyright © 2021 sysfive.com GmbH
##
## GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Check integrity of a password store

check_secrets <directory of password store>

Checks:
- Entries in secrets/.gpg-id must be hexadecimal key ids
- All recipients (entries in secrets/.gpg-id) must have their pubkey in Pubkeys/
- All pubkeys in Pubkeys/ need to be found in secrets/.gpg-id
- All pubkeys in Pubkeys/ must not be expired, else encryption will fail
- All secrets need to be encrypted to all recipients
- No unencrypted files must be in secrets/ (except .gpg-id)
"""
import argparse
import logging
from pathlib import Path
import sys
from typing import List, Tuple

from passwordstore import Passwordstore


def parse() -> argparse.Namespace:
    """Parse arguments when called from command line"""
    parser = argparse.ArgumentParser(description="Check integrity of a password store")
    parser.add_argument(
        "-f",
        "--fail-fast",
        action="store_true",
        help="Fail on first file with encryption errors in a store. "
        "This gives great speedup in case of errors.",
    )
    parser.add_argument("-d", "--debug", action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument(
        "directories",
        default=".",
        nargs=argparse.REMAINDER,
        help="Base directories of password stores to check (the path containing secrets/ and Pubkeys/)",
    )
    return parser.parse_args()


def check_store(base_dir: Path, fail_on_first_file: bool) -> Tuple[bool, List[str]]:
    """Check a password store

    Return True for no errors, else False
    Return Messages of the store check
    """
    pass_store = Passwordstore.create_valid_store(base_dir)
    if pass_store is None:
        return False, ["ERROR: Check of password store revealed fatal errors."]
    errors = pass_store.get_store_errors(fail_on_first_file)
    if len(errors) == 0:
        return True, []
    else:
        return False, errors


def main(args: argparse.Namespace) -> None:
    """Handling of CLI usage"""
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        if args.verbose:
            logging.basicConfig(level=logging.INFO)
    logging.debug(f"args: {args}")
    base_dirs = args.directories
    if not base_dirs:
        base_dirs = ["."]

    stores_successful = []  # type: List[str]
    stores_errors = []  # type: List[str]
    for base_dir in base_dirs:
        dir_path = Path(base_dir).resolve()
        print("-" * 50)
        print(f"Store: {dir_path.name}")
        print("-" * 50)
        success, messages = check_store(
            base_dir=dir_path, fail_on_first_file=args.fail_fast
        )
        logging.debug(f"success: {success}")
        logging.debug(messages)
        if success:
            print("-" * 50)
            print("OK.")
            print("-" * 50)
            stores_successful.append(dir_path.name)
        else:
            print("-" * 50)
            print("ERRORS FOUND.")
            print("-" * 50)
            stores_errors.append(dir_path.name)
            for message in messages:
                print(message)
    print("-" * 50)
    print("Results:")
    print("-" * 50)
    print("Stores successful:")
    print("-" * 50)
    for store in stores_successful:
        print(store)
    print("-" * 50)
    print("Stores with errors:")
    print("-" * 50)
    for store in stores_errors:
        print(store)
    print("-" * 50)
    if len(stores_errors) > 0:
        sys.exit(2)


if __name__ == "__main__":
    main(parse())
