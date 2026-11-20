<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 *
 * The model's own checks of a rule of the Rules tab (models/OPNsense/AppControl/AppControl.php, and
 * library/OPNsense/AppControl/Rules.php that it asks), with stand-ins for OPNsense's BaseModel - whose own
 * validation gives nothing here - its messages, and config.xml's interfaces. No OPNsense needed.
 *
 * What is checked: a source any, an interface's network, an alias, an address, several of them, or one
 * inverted, taken; any with others, an inverted source of more than one item or of any, the firewall itself,
 * an address of one of its interfaces and a table of this plugin's, refused - each on the field it is about,
 * the rule's own reference; only the rules changed, unless the whole model is validated.
 *
 *   php tools/test-model.php
 */

namespace OPNsense\Base\Messages {
    class Message
    {
        public $text;
        public $field;

        public function __construct($text, $field)
        {
            $this->text = $text;
            $this->field = $field;
        }
    }
}

namespace OPNsense\Base {
    class Messages
    {
        public $all = [];

        public function appendMessage($message)
        {
            $this->all[] = [$message->field, $message->text];
        }
    }

    class BaseModel
    {
        public $rules;

        public function performValidation($validateFullModel = false)
        {
            return new Messages();
        }
    }
}

namespace OPNsense\Core {
    class Config
    {
        public static function getInstance()
        {
            return new self();
        }

        public function object()
        {
            return (object)['interfaces' => new class {
                public function children()
                {
                    return ['wan' => (object)[], 'lan' => (object)[], 'opt2' => (object)[]];
                }
            }];
        }
    }
}

namespace {
    if (!function_exists('gettext')) {
        function gettext($text)
        {
            return $text;
        }
    }

    require dirname(__DIR__) . '/src/opnsense/mvc/app/library/OPNsense/AppControl/Rules.php';
    require dirname(__DIR__) . '/src/opnsense/mvc/app/models/OPNsense/AppControl/AppControl.php';

    use OPNsense\AppControl\AppControl;
    use OPNsense\AppControl\Rules;

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

    $interfaces = ['wan' => true, 'lan' => true, 'opt2' => true];
    $taken = ['any', 'opt2', 'Teachers', '192.0.2.5', '2001:db8::/48', 'lan,opt2,Teachers'];
    check(array_map(function ($s) use ($interfaces) {
        return Rules::sourceProblems($s, false, $interfaces);
    }, $taken) === array_fill(0, count($taken), []) && Rules::sourceProblems('Teachers', true, $interfaces) === [],
        'a source taken: any, an interface\'s network, an alias, an address, a network, several at once; one alias inverted');
    check(Rules::sourceProblems('any,lan', false, $interfaces) === [['source', 'Any can not be combined with other aliases']],
        'any with others: refused, as OPNsense\'s own rules refuse it');
    check(Rules::sourceProblems('lan,opt2', true, $interfaces) === [['source_not',
        'Inverting sources is only allowed for single targets to avoid mis-interpretations']],
        'an inverted source of more than one item: refused, on Invert source, as OPNsense\'s own rules refuse it');
    check(Rules::sourceProblems('any', true, $interfaces) === [['source_not',
        'Inverted, any is no device: choose the devices to leave out.']], 'any inverted - no device: refused');
    check(Rules::sourceProblems('(self),lanip,opt9ip,appcontrol_YouTube', false, $interfaces) === [
        ['source', '(self) is the firewall itself, not a device connecting through it.'],
        ['source', 'lanip is the firewall itself, not a device connecting through it.'],
        ['source', 'appcontrol_YouTube is a table of this plugin\'s: it holds servers, not devices.']],
        'the firewall itself, an address of one of its interfaces, a table of this plugin\'s: refused; a name ending in ip ' .
        'that is no interface\'s address left to OPNsense\'s own check');

    function item($uuid, $source, $inverted, $changed)
    {
        return new class ($uuid, $source, $inverted, $changed) {
            public $source;
            public $source_not;
            private $changed;

            public function __construct($uuid, $source, $inverted, $changed)
            {
                $this->source = new class ($source, 'rules.rule.' . $uuid . '.source') {
                    public $__reference;
                    private $value;

                    public function __construct($value, $reference)
                    {
                        $this->value = $value;
                        $this->__reference = $reference;
                    }

                    public function __toString()
                    {
                        return $this->value;
                    }
                };
                $this->source_not = new class ($inverted ? '1' : '0', 'rules.rule.' . $uuid . '.source_not') {
                    public $__reference;
                    private $value;

                    public function __construct($value, $reference)
                    {
                        $this->value = $value;
                        $this->__reference = $reference;
                    }

                    public function __toString()
                    {
                        return $this->value;
                    }
                };
                $this->changed = $changed;
            }

            public function isFieldChanged()
            {
                return $this->changed;
            }
        };
    }

    $model = new AppControl();
    $model->rules = (object)['rule' => new class {
        public function iterateItems()
        {
            yield 'r1' => item('r1', '(self)', false, true);
            yield 'r2' => item('r2', 'lan,opt2', true, true);
            yield 'r3' => item('r3', 'opt2', false, true);
            yield 'r4' => item('r4', 'any,lan', false, false);
        }
    }];
    check($model->performValidation()->all === [
        ['rules.rule.r1.source', '(self) is the firewall itself, not a device connecting through it.'],
        ['rules.rule.r2.source_not', 'Inverting sources is only allowed for single targets to avoid mis-interpretations']],
        'the model: each refusal on its rule\'s own field; a rule unchanged not looked at');
    check(count($model->performValidation(true)->all) === 3, 'the whole model validated: the unchanged rule looked at too');

    echo $failed ? "$failed of $checks checks failed\n" : "$checks checks passed\n";
    exit($failed ? 1 : 0);
}
