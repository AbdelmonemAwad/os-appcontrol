#!/bin/sh
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
# Turn classification on without the settings page - for an image that installs the plugin at first
# boot - the way the page's Save and Apply does it: classify on in config.xml through the plugin's
# own model, then the aliases, the filter, cron and the classifier. On is the default already (the
# plan's svc-5-07); this writes it down and starts it. Classifying itself changes no traffic - the
# classifier reads a copy of it - but an application already chosen in Blocked applications (a
# config.xml restored, say) is blocked once it is on: its block rule loaded, its connections cut.
#
#   install/enable.sh        exit 0 when it is on, 1 when the model refused
set -u

/usr/local/bin/php -r '
require_once "/usr/local/opnsense/mvc/script/load_phalcon.php";
$m = new \OPNsense\AppControl\AppControl();
$m->general->classify = "1";
$bad = [];
foreach ($m->performValidation() as $msg) { $bad[] = $msg->getField() . ": " . $msg->getMessage(); }
if ($bad) { echo "classification left as it was: " . implode("; ", $bad) . "\n"; exit(1); }
$m->serializeToConfig();
\OPNsense\Core\Config::getInstance()->save();
echo "classification turned on\n";
' || exit 1

configctl appcontrol apply > /dev/null 2>&1
configctl filter reload skip_alias > /dev/null 2>&1
configctl cron restart > /dev/null 2>&1
configctl appcontrol restart > /dev/null 2>&1
exit 0
