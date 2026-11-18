<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 *
 * The classifier as one of the firewall's services, and its start at boot.
 *
 * OPNsense starts a plugin's daemons from rc.bootup through plugins_configure('bootup'), which calls
 * the 'bootup' tasks a plugin returns from its _configure() - an rc.conf.d switch alone is read by
 * nothing at boot (os-fanctl, measured on two appliances). So the start is here, guarded by the one
 * setting that decides it: classify, on by default. The setting is read out of $config and not
 * through the model, whose Application tables field asks configd for the installed nDPI's list.
 *
 * No firewall rule is registered: phase 1 classifies and fills tables; blocking is phase 2's.
 */

function appcontrol_enabled()
{
    global $config;

    $general = $config['OPNsense']['AppControl']['general'] ?? [];
    return is_array($general) ? (($general['classify'] ?? '1') === '1') : true;
}

function appcontrol_services()
{
    if (!appcontrol_enabled()) {
        return [];
    }

    return [[
        'description' => gettext('Application Control classifier'),
        'configd' => [
            'restart' => ['appcontrol restart'],
            'start' => ['appcontrol start'],
            'stop' => ['appcontrol stop'],
        ],
        'name' => 'appcontrol',
        'pidfile' => '/var/run/appcontrol.pid',
    ]];
}

function appcontrol_configure()
{
    return [
        'bootup' => ['appcontrol_configure_do'],
    ];
}

function appcontrol_configure_do($verbose = false)
{
    if (!appcontrol_enabled()) {
        return;
    }

    if ($verbose) {
        echo 'Starting the Application Control classifier...';
        flush();
    }

    configd_run('appcontrol start');

    if ($verbose) {
        echo "done.\n";
    }
}
