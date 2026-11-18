#!/usr/local/bin/php
<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 *
 * Make the firewall's aliases say what the settings and the installed nDPI say (library
 * OPNsense\AppControl\Aliases): an External alias with Expire for every category nDPI knows and for
 * each application chosen, while classifying is on; none of this plugin's while it is off. The
 * catalogue of the installed nDPI is read again first (apps.py refresh), and the names come from
 * tables.py, which the classifier uses too.
 *
 *   aliases.php            print a JSON summary; the page's Apply then reloads the filter and cron
 *   aliases.php --remove   every alias of this plugin's taken out (the plugin's removal)
 */

require_once('script/load_phalcon.php');

use OPNsense\AppControl\Aliases;
use OPNsense\Core\Config;
use OPNsense\Firewall\Alias;

function answer($result)
{
    echo json_encode($result) . "\n";
    exit(0);
}

$remove = in_array('--remove', $argv, true);
$refresh = null;
$wanted = [];
$ttl = 3600;
if (!$remove) {
    $out = [];
    exec(escapeshellarg(__DIR__ . '/apps.py') . ' refresh 2>/dev/null', $out);
    $refresh = json_decode(implode("\n", $out), true);
    $out = [];
    exec(escapeshellarg(__DIR__ . '/tables.py') . ' wanted 2>/dev/null', $out, $status);
    $names = json_decode(implode("\n", $out), true);
    if ($status !== 0 || !is_array($names) || !isset($names['aliases']) || !is_array($names['aliases'])) {
        /* without the names nothing here knows which aliases are wanted, so none is touched */
        answer(['status' => 'failed', 'changes' => [], 'errors' => ['the tables the settings ask for could not be read']]);
    }
    $wanted = $names['aliases'];
    $ttl = (int)($names['ttl'] ?? 3600);
}

$model = new Alias();
$done = Aliases::reconcile($model, (string)@file_get_contents('/conf/config.xml'), $wanted, $ttl);
$changes = $done['changes'];

$messages = [];
foreach ($model->performValidation() as $message) {
    $messages[] = $message->getField() . ': ' . $message->getMessage();
}
if (!empty($messages)) {
    answer(['status' => 'failed', 'changes' => [], 'errors' => $messages, 'catalogue' => $refresh]);
}
if (!empty($changes)) {
    $model->serializeToConfig();
    Config::getInstance()->save();
}
answer(['status' => 'ok', 'changes' => $changes, 'notes' => $done['notes'], 'aliases' => count($wanted),
    'catalogue' => $refresh]);
