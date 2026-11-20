#!/bin/sh
# Copyright (C) 2026 Abdelmonem Awad <eg2@live.com>. BSD 2-Clause License.
#
# Run by pkg(8) before the files of os-appcontrol are removed. The rc script that stops the
# classifier, aliases.php that takes the aliases out and cut.py that hands back from hardware what a
# cut dropped are packaged files: by post-deinstall they are gone. So the classifier is stopped here,
# the aliases of the plugin are taken out of Firewall: Aliases through OPNsense's own model - switched
# off instead where a rule or a setting still names one - what was dropped in hardware handed back, and
# the Suricata rules of the Rules tab - no file of the package's - taken out of the Intrusion
# Detection's.
#
# pkg runs the old package's pre-deinstall in an upgrade too, where nothing is to go: the aliases and
# their addresses stay, and the new package's post-install starts the classifier again with the new
# code. PKG_UPGRADE is set in that case and no other.
if [ -n "${PKG_UPGRADE}" ]; then
	exit 0
fi

if [ -x /usr/local/etc/rc.d/appcontrol ]; then
	/usr/local/etc/rc.d/appcontrol onestop > /dev/null 2>&1 || true
fi
# daemon(8) first, which would start the classifier again; the brackets keep the patterns from
# matching the shell that runs this text
/bin/pkill -f 'daemon: [a]ppcontrol\[' 2> /dev/null || true
/bin/pkill -f '/usr/local/opnsense/scripts/[a]ppcontrol/' 2> /dev/null || true
# the tmpfs of the window files, should the rc script not have taken it down
/sbin/umount -f /var/db/os-appcontrol/work 2> /dev/null || true

if [ -f /usr/local/sbin/configctl ]; then
	/usr/local/sbin/configctl appcontrol remove > /dev/null 2>&1 || true
	# no alias of the plugin's switched on now, so no application is blocked: what a cut dropped on the
	# coprocessor is handed back to the host while cut.py is still there
	/usr/local/sbin/configctl appcontrol release > /dev/null 2>&1 || true
	# the Suricata rules of the Rules tab out of the Intrusion Detection's local rules, its rules installed
	# again without them and Suricata told when it runs
	if [ -f /usr/local/etc/suricata/rules/appcontrol.rules ]; then
		rm -f /usr/local/etc/suricata/rules/appcontrol.rules /usr/local/etc/suricata/rules/appcontrol.rules.new
		/usr/local/sbin/configctl ids reload > /dev/null 2>&1 || true
	fi
fi
