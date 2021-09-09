#!/usr/bin/env python3

## pass-helper
## Copyright © 2021 sysfive.com GmbH
##
## GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from datetime import datetime
import logging
import os
from pathlib import Path
import tempfile
import subprocess
from typing import Dict, List, Optional, Set, Tuple, Type, TypeVar

import gpg_helpers

T = TypeVar("T", bound="Passwordstore")


class Passwordstore:
    """Model basic structure of passwordstore and methods to check integrity or add keys

    Always create an instance by create_valid_store()
    """

    def __init__(
        self,
        base_path: Path,
        secrets_path: Path,
        pubkey_path: Path,
        recipients_path: Path,
    ):
        """Create password stores with Passwordstore.create_valid_store(base_path)

        Init assumes the checks of create_valid_store have already been performed.
        """
        # These are pathlib.Path instances, not just strings
        self.base_path = base_path
        self.secrets_path = secrets_path
        self.pubkey_path = pubkey_path
        self.recipients_path = recipients_path

        self.error_messages: List[str] = []

        self.recipient_ids: Set[str] = set()
        with open(self.recipients_path, "r", encoding="utf8") as recipients_file:
            for line_nr, entry in enumerate(recipients_file):
                self.recipient_ids.add(entry.strip())
        logging.info(f"recipients ids: {self.recipient_ids}")
        if line_nr > len(self.recipient_ids) - 1:  # line_nr starts at 0
            self.log_warning(f"There were doubles in {self.secrets_path.name}, fixing!")
            success = self.update_recipients_file(self.recipient_ids)

        # Every pubkey has at least one subkey to which encryption normally takes place.
        # GPG only lists the subkey used for encryption when decrypting.
        # To take account which subkey belongs to which key
        # and that for every main key the files are encrypted to one subkey
        # create a mapping subkey -> main key
        # This also includes main key -> main key
        self.pubkeys: Dict[str, str] = {}

    def log_warning(self, msg: str) -> None:
        logging.warning(msg)

    def log_error(self, msg: str) -> None:
        self.error_messages.append(msg)
        logging.error(msg)

    def log_exception(self, exc: Exception) -> None:
        logging.exception(exc)

    @classmethod
    def create_valid_store(cls: Type[T], base_path: Path) -> Optional[T]:
        """Create a password store instance when basic setup is sane, else return None

        Return None instead of throwing an exception on error as catching that
        exception could hide other errors.
        """
        # Without existing base dir return immediately
        try:
            base_path = base_path.resolve(strict=True)
        except (FileNotFoundError, RuntimeError):
            logging.error(f"Directory not found: {base_path}")
            return None
        if not base_path.is_dir():
            logging.error(f"Is not a directory: {base_path}")
            return None

        # Check all of these
        errors = False
        secrets_path = base_path / "secrets"
        recipients_file = secrets_path / ".gpg-id"
        pubkey_path = base_path / "Pubkeys"
        try:
            secrets_path = secrets_path.resolve(strict=True)
        except (FileNotFoundError, RuntimeError):
            logging.error(f"Secrets directory not found: {secrets_path}")
            errors = True
        if not recipients_file.is_file():
            logging.error(f"Recipients file {recipients_file} is not a regular file!")
            errors = True
        if not pubkey_path.is_dir():
            logging.error(f"Directory for pubkeys does not exist or is no directory!")
            errors = True

        if errors:
            return None
        else:
            return cls(base_path, secrets_path, pubkey_path, recipients_file)

    def check_secrets_path(self, secrets_path: Path, fail_on_first_file: bool) -> None:
        """Check secrets directory

        - Ensure no unencrypted files under secrets/
        - Check that files are encrypted exactly to the specified recipients
        - If fail_on_first_file is True, fail early on first file that's not encrypted
          correctly
        """
        # Check that nothing is unencrypted under secrets/
        logging.info("Checking for unencrypted files.")
        for file_path in secrets_path.glob("**/*"):
            if file_path.is_file():
                file_name = file_path.as_posix()
                if not file_name.endswith(".gpg"):
                    if file_path.name == ".gpg-id" and file_path.parent == secrets_path:
                        continue
                    self.log_error(f"Unencrypted file in secrets: {file_name}")

        # Check encrypted files
        logging.info(
            "Checking that all secrets are encrypted exactly for all recipients."
        )
        args = ["gpg", "--decrypt", "--output=/dev/null"]
        args += gpg_helpers.GPG_OPTS
        env = {
            "LANG": "C",
            "PATH": os.environ["PATH"],
        }
        recipient_ids = self.recipient_ids
        pubkeys = self.pubkeys
        for gpg_file in secrets_path.glob("**/*.gpg"):
            file_ok = True
            gpg_file_name = gpg_file.as_posix()
            logging.info(f"Checking file {gpg_file_name}")
            gpg_args = args + [gpg_file_name]
            try:
                gpg_decrypt = subprocess.run(
                    gpg_args, env=env, capture_output=True, encoding="utf8", check=True
                )
            except subprocess.CalledProcessError as e:
                self.log_error(f"Unable to decrypt {gpg_file_name}")
                self.log_error("Giving up as file can't be unencrypted.)")
                self.log_exception(e)
                break
            else:
                # no exception happened
                logging.debug(gpg_decrypt.stdout)
                logging.debug(gpg_decrypt.stderr)
                encrypted_ids = gpg_helpers.ENCRYPTED_TO_PATTERN.findall(
                    gpg_decrypt.stderr
                )
                logging.debug(f"Encrypted to {len(encrypted_ids)} IDs: {encrypted_ids}")
                encrypted_main_keys: List[str] = []
                for encrypted_id in encrypted_ids:
                    # Encrypted id maps to main key id
                    if encrypted_id not in pubkeys.keys():
                        file_ok = False
                        self.log_error(
                            f"File {gpg_file_name} encrypted to ID {encrypted_id} not in recipients!"
                        )
                    else:
                        encrypted_main_keys.append(pubkeys[encrypted_id])

                for recipient_id in recipient_ids:
                    if recipient_id not in encrypted_main_keys:
                        file_ok = False
                        self.log_error(
                            f"File {gpg_file_name} is not encrypted to {recipient_id}!"
                        )
            if not file_ok and fail_on_first_file:
                logging.debug("Failing early on first non-compliant file.")
                break

    def check_pubkey(self, pubkey_path: Path, valid_ids: Set[str]) -> List[str]:
        """Check pubkey for validity and return the KEY ID that gpg emits

        Return the real ID from gnupg as well as subkey IDs as a list

        - Pubkey Filenames must end in _KEYID.asc, e.g. B003FCB95ACB6D9D.asc
        - IDs must be entered in secrets/.gpg-id, else nothing will be encrypted for them
        - ID must be the ID that gnupg uses (for unambiguity)
        - Key must not be expired
        """
        pubkey_filename = pubkey_path.as_posix()
        logging.debug(f"Checking {pubkey_path}, {pubkey_filename}")
        try:
            key_id = pubkey_path.stem.rsplit("_", 1)[1]
        except IndexError:
            self.log_error("Invalid filename {pubkey_filename}")
            self.log_error(
                "Pubkey files need to end in _KEYID.asc (KEYID:16 hexdigits)"
            )
        else:
            # no exception happened, filename seems valid at first
            if not gpg_helpers.KEY_ID_PATTERN.match(key_id):
                self.log_error(
                    "Filename does not end in valid KEYID: {pubkey_filename}"
                )
                self.log_error(
                    "Pubkey files must end in _KEYID.asc (KEYID=16 hexdigits)"
                )
        if key_id not in valid_ids:
            self.log_error(
                f"Key {pubkey_path.name} with KEY ID {key_id} is in Pubkeys but not in gpg-ids!"
            )
            self.log_error("That key will not be able to decrypt new secrets!")
        # Import pubkey file in temporary keyring to not depend on already imported keys
        # With (context manager) cleans automatically on any exit, even exceptions
        with tempfile.TemporaryDirectory() as tempdir_name:
            my_keyring = Path(tempdir_name, "keyring.kbx")
            my_keyring.touch()
            # Import first
            args = ["gpg", f"--keyring={my_keyring}", "--no-default-keyring"]
            args += gpg_helpers.GPG_OPTS
            args += ["--import", f"{pubkey_filename}"]
            # Parsing stderr output needs fixed language
            env = {
                "LANG": "C",
                "PATH": os.environ["PATH"],
            }
            try:
                gpg_import = subprocess.run(
                    args, env=env, capture_output=True, encoding="utf8", check=True
                )
                logging.debug(gpg_import.stdout)
                logging.debug(gpg_import.stderr)
                output = gpg_import.stderr
            except subprocess.CalledProcessError as e:
                # GPG errors when it tries to import a key and cannot find
                # ultimately trusted keys, so we try to find the ID anyway
                logging.debug(f"GPG import of pubkey {pubkey_filename} returned error!")
                logging.debug(e.stdout)
                logging.debug(e.stderr)
                output = e.stderr
            match = gpg_helpers.REAL_ID_PATTERN.search(output)
            if match:
                real_key_id = match.group("key_id")
                logging.debug(f"Found real key id: {real_key_id}")
                if real_key_id != key_id:
                    self.log_error(
                        f"Public key file {pubkey_filename} uses ID {key_id}, but GPG lists {real_key_id}!"
                    )
                    key_id = real_key_id
            else:
                self.log_error(
                    f"Couldn't receive real GPG ID on importing Public Key file {pubkey_filename}!"
                )
                return [""]  # End testing
            # Test for expiration
            args = [
                "gpg",
                f"--keyring={my_keyring}",
                "--no-default-keyring",
                "--with-colons",
            ]
            args += gpg_helpers.GPG_OPTS
            args += ["--list-keys", key_id]
            env = {
                "LANG": "C",
                "PATH": os.environ["PATH"],
            }
            try:
                gpg_list_key = subprocess.run(
                    args, env=env, capture_output=True, encoding="utf8", check=True
                )
                logging.debug(gpg_list_key.stdout)
                logging.debug(gpg_list_key.stderr)
            except subprocess.CalledProcessError as e:
                self.log_error(f"GPG list-keys of key id {key_id} failed!")
                self.log_exception(e)
                return [""]
            else:
                match = gpg_helpers.EXPIRE_PATTERN.search(gpg_list_key.stdout)
                if match:
                    expiration_date = match.group("expiration")
                    if "T" not in expiration_date:
                        # GPG wants to switch from timestamp to isoformat
                        expiration_date = datetime.fromtimestamp(
                            int(expiration_date)
                        ).isoformat()
                    self.log_error(f"Pubkey {key_id} has expired at {expiration_date}!")
                    return [""]
            gpg_opts = [
                f"--keyring={my_keyring}",
                "--no-default-keyring",
                "--with-colons",
            ] + gpg_helpers.GPG_OPTS
            gpg_fingerprint = gpg_helpers.get_gpg_fingerprint(key_id, gpg_opts)
            logging.debug(gpg_fingerprint)
            ids = gpg_helpers.get_ids_from_fingerprint(gpg_fingerprint)
            logging.debug(f"Key IDs: {ids}")
            if ids[0] != key_id:
                logging.error(f"Recognized ID {ids[0]} instead of {key_id}")
        return ids

    def get_store_errors(self, fail_on_first_file: bool) -> List[str]:
        """Check all integrity features and report errors immediately

        Returns a list of all error messages.

        If possible, check all features at once so one pass is enough.
        """
        base_path = self.base_path  # Symlinks have been resolved already
        recipient_ids = self.recipient_ids
        secrets_path = self.secrets_path
        recipients_path = self.recipients_path

        logging.info(f"Checking store in {base_path}.")
        # Check gpg ids
        bad_ids = gpg_helpers.find_bad_gpg_ids(recipients_path)
        if bad_ids:
            self.log_error("These entries in secrets/.gpg_id are no valid KEY IDs:")
            self.log_error(", ".join(bad_ids))
            self.log_error("KEY IDs are hexadecimal numbers with at least 16 digits.")
        # No need to check invalid IDs for key id
        valid_ids = set(recipient_ids) - set(bad_ids)

        # Check pubkeys
        real_key_ids: List[str] = []
        pubkey_filenames = base_path.glob("Pubkeys/*.asc")
        for pubkey_filename in pubkey_filenames:
            all_ids = self.check_pubkey(pubkey_filename, valid_ids)
            real_key_id = all_ids[0]
            subkeys = all_ids[1:]
            if real_key_id:
                if real_key_id in valid_ids:
                    real_key_ids.append(real_key_id)
                    self.pubkeys[real_key_id] = real_key_id
                    for key in subkeys:
                        self.pubkeys[key] = real_key_id
                else:
                    logging.warn(
                        f"Ignoring pubkey file {pubkey_filename} because ID {real_key_id} not in valid IDs!"
                    )
        logging.info(f"Real key ids: {real_key_ids}")
        logging.info(f"Keys and Subkeys: {self.pubkeys}")

        # Check recipients vs pubkeys
        for recipient_id in recipient_ids:
            if recipient_id not in real_key_ids:
                self.log_error(
                    f"Recipient ID {recipient_id} in {recipients_path.name} not matched in real key ids of pubkeys"
                )

        self.check_secrets_path(secrets_path, fail_on_first_file)

        return self.error_messages

    def update_recipients_file(self, recipients: Set[str]) -> bool:
        """Update .gpg-id file with list of recipients

        Return success as bool
        """
        try:
            with open(self.recipients_path, "w", encoding="utf8") as recipients_file:
                for recipient in sorted(recipients):
                    recipients_file.write(f"{recipient}\n")
        except IOError as e:
            self.log_exception(e)
            return False
        return True

    def encrypt(self, recipients: Set[str]) -> bool:
        """Update gpg-id file and reencrypt to recipients

        Return success as bool
        """
        success = self.update_recipients_file(recipients)
        if not success:
            return False

        # Trigger encryption to the given IDs
        sorted_recipients = sorted(recipients)
        secrets_path = self.secrets_path.as_posix()
        args = ["pass", "init"] + sorted_recipients
        env = {
            "LANG": "C",
            "PATH": os.environ["PATH"],
            "PASSWORD_STORE_DIR": secrets_path,
        }
        try:
            pass_result = subprocess.run(
                args, env=env, capture_output=True, encoding="utf8", check=True
            )
            logging.debug(pass_result.stdout)
            logging.debug(pass_result.stderr)
        except subprocess.CalledProcessError as e:
            logging.error(f"Pass init not successful for {secrets_path}!")
            logging.exception(e)
            logging.error(e.stdout)
            logging.error(e.stderr)
            return False
        return True

    def git_command(self, args: List[str], cwd: Path) -> bool:
        """Git command low-level helper"""
        env = {
            "LANG": "C",
            "PATH": os.environ["PATH"],
        }
        try:
            git_result = subprocess.run(
                args, env=env, cwd=cwd, capture_output=True, encoding="utf8", check=True
            )
            logging.debug(git_result.stdout)
            logging.debug(git_result.stderr)
        except subprocess.CalledProcessError as e:
            logging.error(f"Git not successful!")
            logging.exception(e)
            logging.error(e.stdout)
            logging.error(e.stderr)
            return False
        return True

    def commit_store(self, uid: str, pub_id: str, message: str) -> bool:
        """Commit changes of password store to Git

        Execute in base_path (by using 'cwd' parameter)
        git add --all Pubkeys
        git add --all secrets
        git commit
        """
        cwd = self.base_path

        target = self.secrets_path.name
        args = ["git", "add", "--all", target]
        success = self.git_command(args, cwd)
        if not success:
            return False

        target = self.pubkey_path.name
        args = ["git", "add", "--all", target]
        success = self.git_command(args, cwd)
        if not success:
            return False

        args = ["git", "commit", "-m", message]
        success = self.git_command(args, cwd)

        return success

    def add_key_to_store(
        self,
        uid: str,
        key_ids: List[str],
        pubkey_ascii: str,
        encrypt_always: bool,
        fail_on_first_file: bool,
    ) -> Tuple[bool, List[str]]:
        """Add a pubkey to the key store

        Trigger reencryption if the key is new or with new subkeys
        Check the store in any case
        Prepare a Git commit

        Return success state of the operation as well as list of errors
        """
        errors: List[str] = []
        pub_id = key_ids[0]
        pubkey_changed = True
        pubkey_file_path = self.pubkey_path / f"gpg_public_key_{uid}_{pub_id}.asc"
        with pubkey_file_path.open("w", encoding="utf8") as pubkey_file:
            pubkey_file.write(pubkey_ascii)

        recipients = self.recipient_ids
        if pub_id in recipients and not encrypt_always:
            # Key with pub_id was already in store, check for similarity
            known_subkeys = self.pubkeys.keys()
            for key_id in key_ids:
                if key_id not in known_subkeys:
                    break
            else:
                # No break happened, all subkeys of the key found
                # No reencryption should be needed
                logging.info("All subkeys found, will not trigger reencryption")
                pubkey_changed = False
        else:
            recipients.add(pub_id)

        if pubkey_changed:
            success = self.encrypt(recipients)
            if not success:
                return False, errors
        # Check the validity of store whether added key or not
        errors = self.get_store_errors(fail_on_first_file)
        if len(errors) > 0:
            return False, errors
        success = self.commit_store(uid, pub_id, f"Add key {pub_id} for {uid}")
        if success:
            logging.info("Commit of password store created.")
        else:
            logging.error("Commit of password store not successful!")

        return success, errors
