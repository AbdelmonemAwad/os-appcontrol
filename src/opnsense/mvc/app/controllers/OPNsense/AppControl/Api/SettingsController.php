<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 */

namespace OPNsense\AppControl\Api;

use OPNsense\AppControl\Rules;
use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Core\Backend;
use OPNsense\Core\Config;
use OPNsense\Firewall\Alias;

class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'appcontrol';
    protected static $internalModelClass = '\OPNsense\AppControl\AppControl';

    /**
     * The Rules tab's grid: each rule as the model has it - its action and its source as stored too, for the page
     * to name them - and what it does now: its state, the connections cut for it, its Suricata lines or why it
     * has none (status.py rules).
     */
    public function searchRuleAction()
    {
        $result = $this->searchBase('rules.rule', ['enabled', 'action', 'source', 'source_not', 'app', 'description']);
        $stored = [];
        foreach ($this->getModel()->rules->rule->iterateItems() as $uuid => $rule) {
            $stored[$uuid] = ['action' => (string)$rule->action, 'source' => (string)$rule->source];
        }
        $now = json_decode((string)(new Backend())->configdRun('appcontrol rules'), true);
        $said = is_array($now) && is_array($now['rules'] ?? null) ? $now['rules'] : [];
        foreach ($result['rows'] ?? [] as $i => $row) {
            $uuid = (string)($row['uuid'] ?? '');
            $found = is_array($said[$uuid] ?? null) ? $said[$uuid] : [];
            $suricata = is_array($found['suricata'] ?? null) ? $found['suricata'] : [];
            $result['rows'][$i]['action_key'] = $stored[$uuid]['action'] ?? '';
            $result['rows'][$i]['source_key'] = $stored[$uuid]['source'] ?? '';
            $result['rows'][$i]['state'] = (string)($found['state'] ?? '');
            $result['rows'][$i]['cut'] = (int)($found['cut'] ?? 0);
            $result['rows'][$i]['suricata_lines'] = (int)($suricata['lines'] ?? 0);
            $result['rows'][$i]['suricata_reason'] = (string)($suricata['reason'] ?? '');
        }
        return $result;
    }

    public function getRuleAction($uuid = null)
    {
        return $this->getBase('rule', 'rules.rule', $uuid);
    }

    public function addRuleAction()
    {
        return $this->addBase('rule', 'rules.rule');
    }

    public function setRuleAction($uuid)
    {
        return $this->setBase('rule', 'rules.rule', $uuid);
    }

    public function delRuleAction($uuid)
    {
        return $this->delBase('rules.rule', $uuid);
    }

    public function toggleRuleAction($uuid, $enabled = null)
    {
        return $this->toggleBase('rules.rule', $uuid, $enabled);
    }

    /**
     * What the rule dialog offers for a source (Rules::sourceOptions()): the interfaces of config.xml and the
     * aliases of Firewall: Aliases.
     */
    public function listNetworkSelectOptionsAction()
    {
        $interfaces = [];
        foreach (Config::getInstance()->object()->interfaces->children() as $name => $node) {
            $interfaces[$name] = (string)($node->descr ?? '');
        }
        $aliases = [];
        foreach ((new Alias())->aliases->alias->iterateItems() as $alias) {
            $aliases[] = [(string)$alias->name, (string)$alias->type];
        }
        return Rules::sourceOptions($interfaces, $aliases);
    }
}
