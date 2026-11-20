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
 * removing the plugin leaves nothing behind there. Those of Blocked applications are from any device; a
 * block rule of the Rules tab gives one from its source alone.
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
 * the firewall, from a LAN, a VLAN or a VPN alike, before outbound NAT, on every port - another service on
 * the same address is blocked as well. The firewall's own connections go out, and are not held by it. A
 * blocked application's table never holds the firewall's own addresses, those of its internal networks,
 * nor an address that is not on the internet (classify.py), so the rule cannot shut anyone out of the
 * firewall nor off a host of its own networks; and it takes a server only when the firewall's own resolver
 * gives that address for the name the connection carried, and nothing named the address as an application
 * not blocked (cut.py) - a device cannot write a name to an address of its choosing and so have it blocked
 * for everyone. Priority 1 puts it before the owner's floating, group and interface rules (200000 to
 * 400000, FilterRuleField::getPriority()), as os-blocklists' rules are; quick, so the block is final. It
 * stops new connections only: pf lets a packet of a state it holds through before any rule, so the
 * connections already open are cut by classify.py and cut.py.
 *
 * A block rule of the Rules tab switched on gives the same two rules from its source alone, written as
 * OPNsense's own rules write a source (Rule::mapAddressInfo()): any, an interface's network, an alias, an
 * address or a network - several at once, or one inverted - so that a device outside it is let through to
 * the same servers. An exception for one device is a rule whose source is every device but that one. A
 * source OPNsense cannot read - an alias gone, say - leaves its rule switched off in the ruleset, as it
 * does with its own. Its description says the source, as the page's interfaces are named.
 */
function appcontrol_firewall(Plugin $fw)
{
    global $config;

    if (!appcontrol_enabled()) {
        return;
    }
    $general = $config['OPNsense']['AppControl']['general'] ?? [];
    if (!is_array($general)) {
        $general = [];
    }
    $blocked = [];
    foreach (explode(',', (string)($general['blocked'] ?? '')) as $app) {
        if (trim($app) !== '') {
            $blocked[trim($app)] = true;
        }
    }
    $rules = [];
    foreach (appcontrol_rules() as $rule) {
        if ($rule['enabled'] && $rule['action'] === 'block') {
            $rules[] = $rule;
        }
    }
    if (empty($blocked) && empty($rules)) {
        return;
    }
    $log = (string)($general['block_log'] ?? '0') === '1';
    $prefix = 'Application Control: ';

    $tables = [];
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
        if ((string)$alias->enabled !== '1' || (string)$alias->type !== 'external') {
            continue;
        }
        $tables[$app] = $name;
        if (!isset($blocked[$app])) {
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

    foreach ($rules as $rule) {
        if (!isset($tables[$rule['app']])) {
            continue;
        }
        foreach (['inet', 'inet6'] as $family) {
            $fw->registerFilterRule(1, [
                'ipprotocol' => $family,
                'descr' => $prefix . 'block ' . $rule['app'] . ' from ' . appcontrol_source_text($rule),
                'from' => implode(',', $rule['source']),
                'from_not' => $rule['not'],
                'to' => '<' . $tables[$rule['app']] . '>',
                'direction' => 'in',
                'type' => 'block',
                'log' => $log,
                'quick' => true,
            ]);
        }
    }
}

/*
 * The rules of the Rules tab as config.xml holds them, in their order: [['uuid', 'enabled', 'action', 'app',
 * 'source' => [element], 'not', 'description']]. One with no application, no source or an action of another
 * kind is switched off, as tables.py's rules() has it.
 */
function appcontrol_rules()
{
    global $config;

    $found = $config['OPNsense']['AppControl']['rules']['rule'] ?? [];
    if (!is_array($found)) {
        return [];
    }
    if (isset($found['app']) || isset($found['@attributes'])) {
        /* one rule, read without the list it would make with two */
        $found = [$found];
    }
    $out = [];
    foreach ($found as $rule) {
        if (!is_array($rule)) {
            continue;
        }
        $action = trim((string)($rule['action'] ?? 'block'));
        $app = trim((string)($rule['app'] ?? ''));
        $source = array_values(array_filter(array_map('trim', explode(',', (string)($rule['source'] ?? ''))), 'strlen'));
        $out[] = [
            'uuid' => (string)($rule['@attributes']['uuid'] ?? ''),
            'enabled' => (string)($rule['enabled'] ?? '1') === '1' && in_array($action, ['block', 'alert'], true) &&
                $app !== '' && !empty($source),
            'action' => $action,
            'app' => $app,
            'source' => $source,
            'not' => (string)($rule['source_not'] ?? '0') === '1',
            'description' => (string)($rule['description'] ?? ''),
        ];
    }
    return $out;
}

/*
 * A rule's source as the firewall's pages name it: an interface's network by the interface's description, the
 * rest as written; "not" before it when inverted.
 */
function appcontrol_source_text($rule)
{
    global $config;

    $names = [];
    foreach ($rule['source'] as $element) {
        $interface = $config['interfaces'][$element] ?? null;
        if (is_array($interface)) {
            $names[] = (!empty($interface['descr']) ? $interface['descr'] : strtoupper($element)) . ' net';
        } else {
            $names[] = $element;
        }
    }
    return ($rule['not'] ? 'not ' : '') . implode(', ', $names);
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
