<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 *
 * The rules of the Rules tab: what a source may be, and what the page offers for one.
 *
 * A rule acts on the devices of its source - a block rule of the plugin's from it (plugins.inc.d/appcontrol.inc),
 * the connections the classifier names from there cut, a Suricata rule matching their addresses - so its source
 * names devices that connect through the firewall: any, an interface's network, an alias, an address or a
 * network, as OPNsense's own rules write a source (NetworkAliasField), inverted when it is one item alone.
 */

namespace OPNsense\AppControl;

class Rules
{
    const PREFIX = 'appcontrol_';

    /**
     * Why a rule's source cannot be used - [[field, message]], none when it can: "any" with other items, an
     * inverted source of more than one item or of "any" (the two OPNsense's own rules refuse alike), the
     * firewall itself or an address of one of its interfaces - no device connects through the firewall from
     * there - and a table of this plugin's, which holds servers, not devices. $interfaces: the interfaces of
     * config.xml, [name => true].
     */
    public static function sourceProblems($source, $inverted, array $interfaces)
    {
        $items = array_values(array_filter(array_map('trim', explode(',', (string)$source)), 'strlen'));
        $out = [];
        if (in_array('any', $items, true) && count($items) > 1) {
            $out[] = ['source', gettext('Any can not be combined with other aliases')];
        }
        if ($inverted && count($items) > 1) {
            $out[] = ['source_not', gettext('Inverting sources is only allowed for single targets to avoid mis-interpretations')];
        } elseif ($inverted && $items === ['any']) {
            $out[] = ['source_not', gettext('Inverted, any is no device: choose the devices to leave out.')];
        }
        foreach ($items as $item) {
            if ($item === '(self)' || (substr($item, -2) === 'ip' && isset($interfaces[substr($item, 0, -2)]))) {
                $out[] = ['source', sprintf(gettext('%s is the firewall itself, not a device connecting through it.'), $item)];
            } elseif (strpos($item, self::PREFIX) === 0) {
                $out[] = ['source', sprintf(gettext('%s is a table of this plugin\'s: it holds servers, not devices.'), $item)];
            }
        }
        return $out;
    }

    /**
     * What the page offers for a source, in the form OPNsense's own rule pages give replaceInputWithSelector():
     * a single host or network written by hand; the networks - any, and each interface's; the aliases of
     * addresses and networks, not those of ports nor this plugin's own. $interfaces: [name => description];
     * $aliases: [[name, type]].
     */
    public static function sourceOptions(array $interfaces, array $aliases)
    {
        $networks = [];
        foreach ($interfaces as $name => $description) {
            $networks[$name] = sprintf(gettext('%s network'), $description !== '' ? $description : strtoupper($name));
        }
        natcasesort($networks);
        $names = [];
        foreach ($aliases as $alias) {
            $name = (string)($alias[0] ?? '');
            $type = (string)($alias[1] ?? '');
            if ($name === '' || in_array($type, ['port', 'internal'], true) || strpos($name, self::PREFIX) === 0) {
                continue;
            }
            $names[$name] = $name;
        }
        natcasesort($names);
        return [
            'single' => ['label' => gettext('Single host or Network')],
            'aliases' => ['label' => gettext('Aliases'), 'items' => $names],
            'networks' => ['label' => gettext('Networks'), 'items' => ['any' => gettext('any')] + $networks],
        ];
    }
}
