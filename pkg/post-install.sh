#!/bin/sh
# Copyright (C) 2026 Abdelmonem Awad <eg2@live.com>. BSD 2-Clause License.
#
# Run by pkg(8) after the files of os-appcontrol are in place, on install and on upgrade alike.
# tools/make-package.sh inlines it into the package manifest. The first blocks and the registration
# are what every OPNsense plugin runs; the chmod lines and syntax checks of install/install.sh are
# not repeated, for the reasons os-netreport's post-install gives. The package ndpi is a dependency
# of this one (PLUGIN_DEPENDS), so pkg has installed it already.

if [ -f /usr/local/etc/rc.d/configd ]; then
	/usr/local/etc/rc.d/configd restart
fi

install -d -o root -g wheel -m 0750 /var/db/os-appcontrol

if [ -f /usr/local/opnsense/mvc/script/run_migrations.php ]; then
	/usr/local/opnsense/mvc/script/run_migrations.php OPNsense/AppControl
fi

if [ -x /usr/local/opnsense/scripts/firmware/register.php ]; then
	/usr/local/opnsense/scripts/firmware/register.php install os-appcontrol > /dev/null 2>&1 || true
fi

if [ -f /usr/local/etc/rc.configure_plugins ]; then
	echo "Reloading plugin configuration"
	/usr/local/etc/rc.configure_plugins POST_INSTALL
fi

# The page's place in the menu: the XGS section where os-xgs-npu is installed, Firewall where it is
# not. The menu file is not one of the package's files; place-menu.sh writes it and says which it
# chose.
WHERE=
if [ -x /usr/local/opnsense/scripts/appcontrol/place-menu.sh ]; then
	WHERE=$(/usr/local/opnsense/scripts/appcontrol/place-menu.sh) || WHERE=
fi

# On by default (the plan's svc-5-07), so the page's Apply is done here: the aliases, the filter so pf
# holds their tables, cron so their Expire runs, and the classifier - started again on an upgrade, so
# it runs the new code. Off in Settings, it is stopped.
STATE=
if [ -f /usr/local/sbin/configctl ]; then
	/usr/local/sbin/configctl appcontrol apply > /dev/null 2>&1 || true
	/usr/local/sbin/configctl filter reload skip_alias > /dev/null 2>&1 || true
	/usr/local/sbin/configctl cron restart > /dev/null 2>&1 || true
	if /usr/local/bin/python3 /usr/local/opnsense/scripts/appcontrol/tables.py wanted 2> /dev/null | grep -q '"classify": true'; then
		/usr/local/sbin/configctl appcontrol restart > /dev/null 2>&1 || true
		STATE=" (classifying)"
	else
		/usr/local/sbin/configctl appcontrol stop > /dev/null 2>&1 || true
		STATE=" (classifying is off in Settings)"
	fi
fi

case "${WHERE}" in
xgs)	echo "Application Control installed: the page is at XGS > Application Control${STATE}" ;;
own)	echo "Application Control installed: the page is at Firewall > Application Control${STATE}" ;;
*)	echo "Application Control installed${STATE}; its menu file was not written: run /usr/local/opnsense/scripts/appcontrol/place-menu.sh" ;;
esac
