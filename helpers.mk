## pass-helper
## Copyright © 2021 sysfive.com GmbH
##
## GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

SECRETS_PATH ?= "secrets"
MAIL ?= "unset"
KEY_ID ?= "unset"
# Instead of .git directory, submodules contain  a .git file stating gitdir: path_of_real_gitdir
git_hooks := $(if $(wildcard .git/hooks),.git/hooks,$(word 2,$(file < .git))/hooks)

verify: setup cleanup check_secrets

setup_initial: setup
	touch secrets/.gpg-id
	mkdir -p Pubkeys

autotrust: setup
	pass-helper/autotrust

setup: $(git_hooks)/pre-commit
	. ./env.sh

$(git_hooks)/pre-commit: pass-helper/git_hooks/pre-commit
	cp $? $(git_hooks)

add_user: setup
	SECRETS_PATH=$(SECRETS_PATH) pass-helper/add_user.py --uid $(MAIL) $(KEY_ID)

list_users: setup
	pass-helper/list_users

cleanup: setup
	find $(SECRETS_PATH) -type f -not -name '*.gpg' -not -name '.gpg-id' -exec rm {} +

check_secrets: setup
	./pass-helper/check_secrets.py .

.PHONY: verify autotrust setup setup_initial add_user list_users cleanup
.PHONY: check_secrets
