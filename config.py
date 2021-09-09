#!/usr/bin/env python3

## pass-helper
## Copyright © 2021 sysfive.com GmbH
##
## GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from os import environ
from pathlib import Path

GPG_OPTS = ["--batch", "--no-tty"]
ID_FILE = "secrets/.gpg-id"

if "GNUPGHOME" in environ:
    GPG_HOME = Path(environ["GNUPGHOME"])
else:
    GPG_HOME = Path.home() / ".gnupg"
