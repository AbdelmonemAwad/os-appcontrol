<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 *
 * The aliases behind Application Control's pf tables, written in config.xml through OPNsense's own
 * Alias model, the way os-blocklists writes its own: each of type External - a table pf holds and
 * the classifier fills - with Expire, so OPNsense's own cron empties an address of it once it has
 * not been seen for that long (pfctl -T expire). That is the kind of alias Firewall: Rules offers
 * in a rule's source and destination, and XGS: Settings' "Cut open connections when listed" can
 * name (phase 0's lab, L9, on an XGS 3300).
 *
 * The aliases this plugin owns are named appcontrol_ and described 'Application Control: '; any
 * other is the owner's and is never touched, whatever its name. Which ones are wanted is decided by
 * tables.py - one place for their names - and given here.
 */

namespace OPNsense\AppControl;

class Aliases
{
    const PREFIX = 'appcontrol_';
    const DESCRIPTION = 'Application Control: ';

    /**
     * An alias this plugin made: its name and its description both say so.
     */
    public static function owned($name, $description)
    {
        return strpos((string)$name, self::PREFIX) === 0 && strpos((string)$description, self::DESCRIPTION) === 0;
    }

    /**
     * Make the model's aliases say what $wanted says - [name => ['description' => text]], each of type
     * External with Expire $ttl - and return ['changes' => what changed, 'notes' => what was left as it
     * is and why], one line each. An alias of this plugin's no longer wanted is removed; when something
     * else in the configuration names it or holds its uuid - a rule, XGS: Settings' cut list - it is
     * switched off instead, so nothing of the owner's is left pointing at nothing. $config is
     * config.xml's text, read for those references. Nothing is saved here: the caller validates and
     * saves, and only when something changed.
     */
    public static function reconcile($model, $config, array $wanted, $ttl)
    {
        $changes = [];
        $notes = [];
        $ttl = (string)max(60, (int)$ttl);
        foreach (iterator_to_array($model->aliases->alias->iterateItems()) as $uuid => $alias) {
            $name = (string)$alias->name;
            if (!self::owned($name, (string)$alias->description) || isset($wanted[$name])) {
                continue;
            }
            $named = preg_match_all('/\b' . preg_quote($name, '/') . '\b/', (string)$config) > 1;
            $held = substr_count((string)$config, (string)$uuid) > 1;
            if ($named || $held) {
                if ((string)$alias->enabled !== '0') {
                    $alias->enabled = '0';
                    $changes[] = $name . ': no longer wanted, but named elsewhere in the configuration - switched off, not removed';
                }
            } else {
                $model->aliases->alias->del($uuid);
                $changes[] = $name . ': removed';
            }
        }
        foreach ($wanted as $name => $want) {
            $values = [
                'enabled' => '1',
                'type' => 'external',
                'expire' => $ttl,
                'description' => (string)($want['description'] ?? (self::DESCRIPTION . $name)),
            ];
            $node = $model->getByName($name);
            if ($node === null) {
                $node = $model->aliases->alias->Add();
                $node->setNodes(['name' => $name] + $values);
                $changes[] = $name . ': added';
                continue;
            }
            if (!self::owned($name, (string)$node->description)) {
                $notes[] = $name . ': an alias of this name is not one of this plugin\'s - left as it is';
                continue;
            }
            $was = [];
            foreach (array_keys($values) as $field) {
                $was[$field] = (string)$node->$field;
            }
            if ($was !== $values) {
                $node->setNodes($values);
                $changes[] = $name . ($was['expire'] !== $values['expire'] ? ': expiry ' . $values['expire'] . ' s' : ': updated');
            }
        }
        return ['changes' => $changes, 'notes' => $notes];
    }
}
