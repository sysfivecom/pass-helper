## pass-helper
## Copyright © 2021 sysfive.com GmbH
##
## GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# Makefile for pass-helper itself, not loaded by pass stores
# Don't clutter recipes with \s
.ONESHELL:
.SHELLFLAGS = -ce
# Instead of .git directory, submodules contain  a .git file stating gitdir: path_of_real_gitdir
git_hooks := $(if $(wildcard .git/hooks),.git/hooks,$(word 2,$(file < .git))/hooks)
venv_python = $(wildcard .venv/lib/*)

all: get_deps tests

get_deps: $(git_hooks)/pre-commit

clean:
	@rm $(git_hooks)/pre-commit
	echo Git hook removed.

tests: fast_checks pytest_tests

pytest_tests: pytest
	.venv/bin/python3 -m pytest

pytest: .venv $(venv_python)/pytest

$(venv_python)/pytest:
	.venv/bin/pip install pytest

$(git_hooks)/pre-commit: .pre-commit-config.yaml install_hook fast_checks

install_hook: .venv
	. .venv/bin/activate
	pip install pre-commit
	pre-commit install --install-hooks --overwrite

fast_checks: install_hook
	. .venv/bin/activate
	pre-commit run --all-files

.venv:
	python3 -m venv .venv
	# Pip < 20 will break on 'bdist_wheel'
	.venv/bin/pip install --upgrade pip

get_deps: $(git_hooks)/pre-commit

.PHONY: tests get_deps install_hook fast_checks
