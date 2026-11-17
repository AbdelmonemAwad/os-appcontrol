#!/bin/sh
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
# Remove the Application Control plugin: the classifier stopped, its aliases taken out of
# Firewall: Aliases - switched off instead where a rule or a setting still names one - its files, its
# state in /var/db/os-appcontrol, and the addresses its tables held. Kept: the settings in config.xml,
# and the package ndpi unless install/install.sh installed it and no other package needs it.

# the classifier and its aliases first, while the files that stop and remove them are there
/usr/local/etc/rc.d/appcontrol onestop > /dev/null 2>&1 || true
# a classifier the rc script did not find - daemon(8) first, which would start it again - and what it
# started; the brackets keep the patterns from matching a shell that carries this text
/bin/pkill -f 'daemon: [a]ppcontrol\[' 2> /dev/null || true
/bin/pkill -f '/usr/local/opnsense/scripts/[a]ppcontrol/' 2> /dev/null || true
configctl appcontrol remove > /dev/null 2>&1 || true

NDPI=
[ -f /usr/local/share/os-appcontrol/ndpi-installed ] && NDPI=ours

# the hook and the rc script, then everything else src/ lays down
rm -f /usr/local/etc/inc/plugins.inc.d/appcontrol.inc
rm -f /usr/local/etc/rc.d/appcontrol
rm -rf /usr/local/share/os-appcontrol
rm -f /usr/local/opnsense/service/conf/actions.d/actions_appcontrol.conf
rm -rf /usr/local/opnsense/scripts/appcontrol
# the menu file place-menu.sh wrote, which is not one of src/'s files
rm -f /usr/local/opnsense/mvc/app/models/OPNsense/AppControl/Menu/Menu.xml
rmdir /usr/local/opnsense/mvc/app/models/OPNsense/AppControl/Menu 2>/dev/null || true
rm -rf /usr/local/opnsense/mvc/app/models/OPNsense/AppControl
rm -rf /usr/local/opnsense/mvc/app/controllers/OPNsense/AppControl
rm -rf /usr/local/opnsense/mvc/app/views/OPNsense/AppControl
rm -rf /usr/local/opnsense/mvc/app/library/OPNsense/AppControl
# what the classifier kept, and its pidfiles if it had to be killed; the tmpfs of its window files
# first, should the rc script not have taken it down
/sbin/umount -f /var/db/os-appcontrol/work 2> /dev/null || true
rm -rf /var/db/os-appcontrol
rm -f /var/run/appcontrol.pid /var/run/appcontrol.daemon.pid
service configd restart > /dev/null
# PHP keeps them in its own temporary directory on 26.7 (/var/lib/php/tmp); /tmp is where they were
rm -f /var/lib/php/tmp/opnsense_menu_cache.xml /var/lib/php/tmp/opnsense_acl_cache.json \
    /tmp/opnsense_menu_cache.xml /tmp/opnsense_acl_cache.json
configctl filter reload skip_alias > /dev/null 2>&1 || true
configctl cron restart > /dev/null 2>&1 || true
# The tables of the plugin's aliases that are gone, emptied when no rule uses them: a table outlives
# its alias and goes on holding the addresses (os-blocklists, 2026-10-29). One whose alias is still in
# Firewall: Aliases - switched off, as something names it - is OPNsense's to keep.
/sbin/pfctl -v -s Tables 2> /dev/null | awk '$2 ~ /^appcontrol_/ && $1 !~ /r/ { print $2 }' |
while read -r table; do
    grep -q "<name>${table}</name>" /conf/config.xml 2> /dev/null && continue
    /sbin/pfctl -t "${table}" -T flush > /dev/null 2>&1 || true
done

if [ "${NDPI}" = ours ]; then
    if [ -z "$(pkg query '%rn' ndpi 2> /dev/null)" ]; then
        pkg delete -y ndpi > /dev/null 2>&1 && echo "The package ndpi, which install/install.sh installed, removed."
    else
        echo "The package ndpi stays: another package needs it."
    fi
fi
echo "Application Control removed; its settings stay in config.xml"
