<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 *
 * The classifier as one of the firewall's services, its start at boot, and the block rules of the
 * applications chosen in Blocked applications.
 *
 * OPNsense starts a plugin's daemons from rc.bootup through plugins_configure('bootup'), which calls
 * the 'bootup' tasks a plugin returns from its _configure() - an rc.conf.d switch alone is read by
 * nothing at boot (os-fanctl, measured on two appliances). So the start is here, guarded by the one
 * setting that decides it: classify, on by default. The setting is read out of $config and not
 * through the model, whose Application tables field asks configd for the installed nDPI's list.
 *
 * The block rules (appcontrol_firewall()) are registered at every filter reload, the way os-blocklists
 * registers its own: never among the owner's rules in Firewall: Rules, so turning blocking off or
 * removing the plugin leaves nothing behind there.
 */

use OPNsense\Firewall\Alias;
use OPNsense\Firewall\Plugin;

function appcontrol_enabled()
{
    global $config;

    $general = $config['OPNsense']['AppControl']['general'] ?? [];
    return is_array($general) ? (($general['classify'] ?? '1') === '1') : true;
}

/*
 * One block rule for each family, IPv4 and IPv6, for each application chosen in Blocked applications whose
 * table is in Firewall: Aliases - an alias of this plugin's (named appcontrol_ and described "Application
 * Control: " and the application's name), External, switched on - while classifying is on. With classifying
 * off the plugin's aliases are gone, and so are the rules.
 *
 *     block in quick to <appcontrol_<application>>   on every interface, described "Application Control:
 *                                                     block <application>", logged when Log what is blocked
 *                                                     is on
 *
 * Inbound on every interface: a packet a device sends to a server in the table is dropped where it enters
 * the firewall, from a LAN, a VLAN or a VPN alike, before outbound NAT. The firewall's own connections go
 * out, and are not held by it. A table never holds the firewall's own addresses nor those of its internal
 * networks (classify.py), so the rule cannot shut anyone out of the firewall. Priority 1 puts it before the
 * owner's floating, group and interface rules (200000 to 400000, FilterRuleField::getPriority()), as
 * os-blocklists' rules are; quick, so the block is final - an exception for one device is phase 3's (the
 * plan's top-01). It stops new connections only: pf lets a packet of a state it holds through before any
 * rule, so the connections already open are cut by classify.py and cut.py.
 */
function appcontrol_firewall(Plugin $fw)
{
    global $config;

    if (!appcontrol_enabled()) {
        return;
    }
    $general = $config['OPNsense']['AppControl']['general'] ?? [];
    if (!is_array($general)) {
        return;
    }
    $blocked = [];
    foreach (explode(',', (string)($general['blocked'] ?? '')) as $app) {
        if (trim($app) !== '') {
            $blocked[trim($app)] = true;
        }
    }
    if (empty($blocked)) {
        return;
    }
    $log = (string)($general['block_log'] ?? '0') === '1';
    $prefix = 'Application Control: ';

    foreach ((new Alias())->aliases->alias->iterateItems() as $alias) {
        $name = (string)$alias->name;
        $description = (string)$alias->description;
        /* this plugin's own, and an application's - a category's description begins with "category " */
        if (strpos($name, 'appcontrol_') !== 0 || strpos($description, $prefix) !== 0) {
            continue;
        }
        $app = substr($description, strlen($prefix));
        if (strpos($name, 'appcontrol_cat_') === 0 && strpos($app, 'category ') === 0) {
            continue;
        }
        if (!isset($blocked[$app]) || (string)$alias->enabled !== '1' || (string)$alias->type !== 'external') {
            continue;
        }
        foreach (['inet', 'inet6'] as $family) {
            $fw->registerFilterRule(1, [
                'ipprotocol' => $family,
                'descr' => $prefix . 'block ' . $app,
                'to' => '<' . $name . '>',
                'direction' => 'in',
                'type' => 'block',
                'log' => $log,
                'quick' => true,
            ]);
        }
    }
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
