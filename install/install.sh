#!/bin/sh
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
# Install the Application Control plugin from a copy of this repository on the firewall:
#   sh install/install.sh
# Safe to run again after an update: settings in config.xml are kept. Classifying is on by default,
# so once this has run the classifier reads the internal interfaces and the category tables fill,
# with nothing set; nothing is blocked.

set -e
HERE=$(cd "$(dirname "$0")/.." && pwd)

# Syntax first, on the tree about to be copied, so nothing with an error is ever copied - as
# os-blocklists found (2026-10-29). The Python is compiled into a directory of its own, removed after,
# not beside the tree's files.
for f in $(find "${HERE}/src" -name '*.php' -o -name '*.inc'); do
    php -l "$f" > /dev/null
done
PYC=$(mktemp -d -t os-appcontrol-check)
trap 'rm -rf "${PYC}"' EXIT
for f in $(find "${HERE}/src" -name '*.py'); do
    PYTHONPYCACHEPREFIX="${PYC}" python3 -m py_compile "$f"
done
rm -rf "${PYC}"
trap - EXIT

# The engine: ndpiReader, from OPNsense's own package ndpi, which installs with nothing else (OPNsense
# 26.7.9). Installed here when it is not there, and marked so: the removal takes it away again only
# when this installed it and no other package needs it. Without it the classifier waits and says so.
install -d -m 0755 /usr/local/share/os-appcontrol
if ! pkg info -e ndpi > /dev/null 2>&1; then
    if pkg install -y ndpi > /dev/null 2>&1; then
        echo "installed by install/install.sh" > /usr/local/share/os-appcontrol/ndpi-installed
    else
        echo "The package ndpi could not be installed (pkg install ndpi): the classifier waits for it."
    fi
fi

# plugin files: src/ maps to /usr/local
# The public keys a release must be signed with for self-update.py to install it (its SIGNED
# RELEASES) are the set this tree holds and no other: the installed ones go first, so a key the tree
# dropped goes with this install.
rm -rf /usr/local/opnsense/scripts/appcontrol/release-keys
cp -R "${HERE}/src/" /usr/local/
chmod 644 /usr/local/opnsense/scripts/appcontrol/release-keys/*.pub
chmod 755 /usr/local/opnsense/scripts/appcontrol/*.py /usr/local/opnsense/scripts/appcontrol/aliases.php \
    /usr/local/opnsense/scripts/appcontrol/place-menu.sh /usr/local/etc/rc.d/appcontrol
chmod 644 /usr/local/opnsense/scripts/appcontrol/categories.json \
    /usr/local/opnsense/scripts/appcontrol/i18n/ui/source.json /usr/local/opnsense/scripts/appcontrol/menu/*.xml
chmod 644 /usr/local/etc/inc/plugins.inc.d/appcontrol.inc \
    /usr/local/opnsense/service/conf/actions.d/actions_appcontrol.conf

# The page's place in the menu: the XGS section where os-xgs-npu is installed, Firewall where it is
# not. place-menu.sh writes the menu file and says which it chose: "xgs" or "own".
WHERE=$(/usr/local/opnsense/scripts/appcontrol/place-menu.sh)

install -d -o root -g wheel -m 0750 /var/db/os-appcontrol

# reload configd actions, menu and ACL caches
service configd restart > /dev/null
# PHP keeps them in its own temporary directory on 26.7 (/var/lib/php/tmp); /tmp is where they were
rm -f /var/lib/php/tmp/opnsense_menu_cache.xml /var/lib/php/tmp/opnsense_acl_cache.json \
    /tmp/opnsense_menu_cache.xml /tmp/opnsense_acl_cache.json

# What the page's Apply does: the aliases made to say what the settings say, the filter reloaded so
# pf holds their tables, cron so their Expire runs, then the classifier started - or stopped, when
# classifying was turned off before.
configctl appcontrol apply > /dev/null 2>&1 || true
configctl filter reload skip_alias > /dev/null 2>&1 || true
configctl cron restart > /dev/null 2>&1 || true
if python3 /usr/local/opnsense/scripts/appcontrol/tables.py wanted 2> /dev/null | grep -q '"classify": true'; then
    configctl appcontrol restart > /dev/null 2>&1 || true
    STATE="classifying"
else
    configctl appcontrol stop > /dev/null 2>&1 || true
    STATE="classifying is off in Settings"
fi

# What this install is, for the self-update: the commit, from a git checkout, or from the
# .source-commit stamp that an xgs-image-builder image or the self-update leaves in the tree.
# Without either it is recorded as unknown, and the self-update takes the latest release once.
REV=; RDATE=; RSRC=unknown
if [ -e "${HERE}/.git" ] && REV=$(git -C "${HERE}" rev-parse HEAD 2>/dev/null); then
    RDATE=$(git -C "${HERE}" log -1 --format=%cI 2>/dev/null); RSRC=git
elif [ -s "${HERE}/.source-commit" ]; then
    read -r REV RDATE _ < "${HERE}/.source-commit"; RSRC=stamp
else
    REV=
fi
case ${REV} in *[!0-9a-f]*) REV=; RDATE=; RSRC=unknown ;; esac
printf '{"commit": "%s", "date": "%s", "source": "%s", "installed_at": %s}\n' \
    "${REV}" "${RDATE}" "${RSRC}" "$(date +%s)" > /usr/local/share/os-appcontrol/installed.json

if [ "${WHERE}" = xgs ]; then
    echo "Application Control installed: XGS > Application Control (${STATE})"
else
    echo "Application Control installed: Firewall > Application Control (${STATE})"
fi
