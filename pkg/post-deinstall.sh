#!/bin/sh
# Copyright (C) 2026 Abdelmonem Awad <eg2@live.com>. BSD 2-Clause License.
#
# Run by pkg(8) after the files of os-appcontrol have been removed; not during an upgrade. The
# classifier was stopped and the aliases taken out in pre-deinstall, while the files that do it were
# there. Kept: the settings in config.xml, and the package ndpi, which pkg autoremove takes once
# nothing needs it.

if [ -x /usr/local/opnsense/scripts/firmware/register.php ]; then
	/usr/local/opnsense/scripts/firmware/register.php remove os-appcontrol > /dev/null 2>&1 || true
fi

if [ -f /usr/local/etc/rc.d/configd ]; then
	/usr/local/etc/rc.d/configd restart
fi

if [ -f /usr/local/etc/rc.configure_plugins ]; then
	echo "Reloading plugin configuration"
	/usr/local/etc/rc.configure_plugins POST_DEINSTALL
fi

# The menu file place-menu.sh wrote is not one of the package's files, so pkg left it, and the
# model's directory with it. The menu is cached by PHP in /var/lib/php/tmp on 26.7, in /tmp before.
rm -f /usr/local/opnsense/mvc/app/models/OPNsense/AppControl/Menu/Menu.xml
rmdir /usr/local/opnsense/mvc/app/models/OPNsense/AppControl/Menu /usr/local/opnsense/mvc/app/models/OPNsense/AppControl 2>/dev/null || true
rm -f /var/lib/php/tmp/opnsense_menu_cache.xml /tmp/opnsense_menu_cache.xml

# Nor what Python compiles beside a script it imports, which would keep the scripts' directory, nor
# what the classifier kept - its tmpfs taken down first, if it is still there - nor its pidfiles if it
# had to be killed; the plugin's directories go once empty.
/sbin/umount -f /var/db/os-appcontrol/work 2> /dev/null || true
rm -rf /usr/local/opnsense/scripts/appcontrol/__pycache__ /var/db/os-appcontrol
rm -f /var/run/appcontrol.pid /var/run/appcontrol.daemon.pid
for d in /usr/local/opnsense/scripts/appcontrol /usr/local/opnsense/mvc/app/library/OPNsense/AppControl; do
	[ -d "${d}" ] && find "${d}" -depth -type d -empty -delete 2> /dev/null
done

[ -f /usr/local/sbin/configctl ] && /usr/local/sbin/configctl filter reload skip_alias > /dev/null 2>&1 || true
[ -f /usr/local/sbin/configctl ] && /usr/local/sbin/configctl cron restart > /dev/null 2>&1 || true

# The tables of the plugin's aliases that are gone, taken out of pf when no rule uses them: a table outlives
# its alias and goes on holding the addresses (os-blocklists, 2026-10-29). One whose alias is still in
# Firewall: Aliases - switched off, as something names it - is OPNsense's to keep.
/sbin/pfctl -v -s Tables 2> /dev/null | awk '$2 ~ /^appcontrol_/ && $1 !~ /r/ { print $2 }' |
while read -r table; do
	grep -q "<name>${table}</name>" /conf/config.xml 2> /dev/null && continue
	/sbin/pfctl -t "${table}" -T kill > /dev/null 2>&1 || true
done

echo "Application Control removed; its settings stay in config.xml"
