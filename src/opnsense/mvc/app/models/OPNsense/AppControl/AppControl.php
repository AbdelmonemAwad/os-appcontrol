<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 */

namespace OPNsense\AppControl;

use OPNsense\Base\BaseModel;
use OPNsense\Base\Messages\Message;
use OPNsense\Core\Config;

class AppControl extends BaseModel
{
    /**
     * The model's own checks, and a rule's source as Rules::sourceProblems() takes it: the firewall itself - an
     * address config.xml gives it among them - and its tables refused, an inverted source of one item alone.
     */
    public function performValidation($validateFullModel = false)
    {
        $messages = parent::performValidation($validateFullModel);
        $config = Config::getInstance()->object();
        $interfaces = [];
        foreach ($config->interfaces->children() as $name => $node) {
            $interfaces[$name] = true;
        }
        $own = Rules::ownAddresses($config);
        foreach ($this->rules->rule->iterateItems() as $rule) {
            if (!$validateFullModel && !$rule->isFieldChanged()) {
                continue;
            }
            $problems = Rules::sourceProblems((string)$rule->source, (string)$rule->source_not === '1', $interfaces, $own);
            foreach ($problems as $problem) {
                $field = $problem[0];
                $messages->appendMessage(new Message($problem[1], $rule->$field->__reference));
            }
        }
        return $messages;
    }
}
