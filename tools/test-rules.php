<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 *
 * The block rules plugins.inc.d/appcontrol.inc registers, with stand-ins for OPNsense's Firewall\Plugin
 * (which records each rule and orders them as 26.7's does: by priority, then in the order registered)
 * and Firewall\Alias (the aliases given here), as os-blocklists' tools/test-rules.php has them. No
 * OPNsense needed.
 *
 * What is checked: one rule for each family for each application chosen in Blocked applications whose
 * alias of the plugin's is in Firewall: Aliases, switched on and External - block, in, quick, to its
 * table, on no interface, priority 1, described "Application Control: block" and its name, logged as
 * the setting says; none for an application not chosen, one chosen whose alias is not made yet, an
 * alias switched off, a category's alias, an owner's alias of the same name, or an alias of another
 * kind; none at all with classifying off, nothing chosen, or no settings; and the start at boot left
 * as it was.
 *
 *   php tools/test-rules.php
 */

namespace OPNsense\Firewall {
    class Plugin
    {
        public $rules = [];

        public function registerFilterRule($prio, $conf)
        {
            $this->rules[] = [$prio, count($this->rules), $conf];
        }

        /* 26.7: ksort() of the priorities, each priority's rules in the order registered */
        public function ordered()
        {
            $rules = $this->rules;
            usort($rules, function ($a, $b) {
                return [$a[0], $a[1]] <=> [$b[0], $b[1]];
            });
            return $rules;
        }
    }

    class AliasItems
    {
        public $items;

        public function iterateItems()
        {
            foreach ($this->items as $i => $item) {
                yield 'uuid-' . $i => $item;
            }
        }
    }

    class Alias
    {
        public static $given = [];
        public $aliases;

        public function __construct()
        {
            $this->aliases = (object)['alias' => new AliasItems()];
            $this->aliases->alias->items = array_map(function ($a) {
                return (object)$a;
            }, self::$given);
        }
    }
}

namespace {
    $root = dirname(__DIR__);
    $failed = 0;
    $checks = 0;

    function check($ok, $what)
    {
        global $failed, $checks;
        $checks++;
        if (!$ok) {
            $failed++;
            echo "FAIL $what\n";
        } else {
            echo "ok   $what\n";
        }
    }

    function configd_run($what)
    {
        $GLOBALS['configd'][] = $what;
    }

    if (!function_exists('gettext')) {
        function gettext($text)
        {
            return $text;
        }
    }

    require $root . '/src/etc/inc/plugins.inc.d/appcontrol.inc';

    function alias($name, $description, $more = [])
    {
        return $more + ['name' => $name, 'description' => $description, 'enabled' => '1', 'type' => 'external'];
    }

    /* the rules for the settings and aliases given: [[priority, order, rule]] as the filter writes them */
    function rules($general, $aliases)
    {
        global $config;
        $config = $general === null ? [] : ['OPNsense' => ['AppControl' => ['general' => $general]]];
        \OPNsense\Firewall\Alias::$given = $aliases;
        $fw = new \OPNsense\Firewall\Plugin();
        appcontrol_firewall($fw);
        return $fw->ordered();
    }

    $aliases = [
        alias('appcontrol_cat_Media', 'Application Control: category Media'),
        alias('appcontrol_YouTube', 'Application Control: YouTube'),
        alias('appcontrol_TikTok', 'Application Control: TikTok'),
        alias('appcontrol_Netflix', 'Application Control: Netflix', ['enabled' => '0']),
        alias('appcontrol_DNS', 'my own DNS servers'),
        alias('appcontrol_Steam', 'Application Control: Steam', ['type' => 'host']),
        alias('appcontrol_IoT_Scada', 'Application Control: IoT-Scada'),
        alias('office', 'Application Control: Dropbox'),
        /* the owner's, by the plugin's kind of name, its description as long as the plugin's prefix before "Skype" */
        alias('appcontrol_Skype', 'My hand-made list of Skype'),
    ];
    $blocked = 'YouTube,Media,category Media,Netflix,DNS,Steam,IoT-Scada,Dropbox,Zoom,Skype';

    /* the rules: YouTube and IoT-Scada, by their aliases; nothing else */
    $all = rules(['classify' => '1', 'blocked' => $blocked, 'block_log' => '0'], $aliases);
    $rules = array_map(function ($r) {
        return $r[2];
    }, $all);
    check(array_column($rules, 'descr') === ['Application Control: block YouTube', 'Application Control: block YouTube',
        'Application Control: block IoT-Scada', 'Application Control: block IoT-Scada'],
        'blocked: YouTube and IoT-Scada, by their aliases - two rules each, described with the application\'s name; ' .
        'none for TikTok (not chosen), a category, Netflix (its alias switched off), DNS and Skype (aliases of the ' .
        'owner\'s by those names), Steam (not External), Dropbox (an alias not of this plugin\'s name), Zoom (no alias yet)');
    check(array_column($rules, 'ipprotocol') === ['inet', 'inet6', 'inet', 'inet6'], 'each family, IPv4 and IPv6');
    $first = $rules[0];
    check($first['to'] === '<appcontrol_YouTube>' && !isset($first['from']), 'from anywhere to the application\'s table');
    check($first['type'] === 'block' && $first['direction'] === 'in' && $first['quick'] === true,
        'block, inbound - where a device\'s packet enters the firewall - and quick, so the block is final');
    check(!isset($first['interface']), 'on no interface: every interface\'s devices, a LAN, a VLAN or a VPN alike');
    check(array_unique(array_column($all, 0)) === [1], 'priority 1: before the owner\'s rules, as os-blocklists\' rules');
    check($first['log'] === false && !isset($first['label']),
        'not logged with Log what is blocked off; no label of its own (OPNsense hashes one)');
    check($rules[2]['to'] === '<appcontrol_IoT_Scada>', 'the table as the alias names it: IoT-Scada\'s is appcontrol_IoT_Scada');

    $rules = array_map(function ($r) {
        return $r[2];
    }, rules(['classify' => '1', 'blocked' => 'YouTube', 'block_log' => '1'], $aliases));
    check(count($rules) === 2 && $rules[0]['log'] === true && $rules[1]['log'] === true, 'Log what is blocked on: both logged');

    check(rules(['classify' => '0', 'blocked' => $blocked], $aliases) === [], 'classifying off: no rule');
    check(rules(['classify' => '1', 'blocked' => ''], $aliases) === [], 'nothing chosen to be blocked: no rule');
    check(rules(['classify' => '1'], $aliases) === [], 'no Blocked applications in config.xml: no rule');
    check(rules(null, $aliases) === [], 'no settings of the plugin\'s at all: no rule');
    check(count(rules(['blocked' => 'YouTube'], $aliases)) === 2, 'classify not in config.xml - on by default: the rules');
    check(rules(['classify' => '1', 'blocked' => ' , ,'], $aliases) === [], 'a list of commas and spaces: no rule');

    /* the start at boot: still only when classifying is on */
    $GLOBALS['configd'] = [];
    $config = ['OPNsense' => ['AppControl' => ['general' => ['classify' => '0']]]];
    appcontrol_configure_do();
    $off = $GLOBALS['configd'];
    $config = ['OPNsense' => ['AppControl' => ['general' => ['classify' => '1']]]];
    appcontrol_configure_do();
    check($off === [] && $GLOBALS['configd'] === ['appcontrol start'], 'at boot: the classifier started when classifying is on, only');
    check(count(appcontrol_services()) === 1, 'the classifier one of the firewall\'s services while it classifies');

    echo $failed ? "$failed of $checks checks failed\n" : "$checks checks passed\n";
    exit($failed ? 1 : 0);
}
