<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 *
 * The aliases behind the tables (library OPNsense\AppControl\Aliases, and scripts/appcontrol/aliases.php
 * that runs it), with stand-ins for what they reach of OPNsense: the Alias model - its aliases, Add(),
 * del(), getByName(), setNodes(), performValidation(), serializeToConfig() - and Config's save(), as
 * the lab's L9 used them on an XGS 3300 to make an External alias with Expire.
 *
 * What is checked: an alias made External with Expire for each table wanted; its Expire refreshed when
 * the setting changes, and nothing written when nothing changed; on removal, every alias of the
 * plugin's taken out - switched off instead when a rule or a setting still names it - and none of the
 * owner's touched, whatever its name; aliases.php saving only after a clean validation, and touching
 * nothing when the names cannot be read.
 *
 *   php tools/test-aliases.php
 */

namespace OPNsense\Base\Messages {
    class Message
    {
        private $message;
        private $field;

        public function __construct($message, $field = '')
        {
            $this->message = $message;
            $this->field = $field;
        }

        public function getMessage()
        {
            return $this->message;
        }

        public function getField()
        {
            return $this->field;
        }
    }
}

namespace OPNsense\Firewall {
    /* one alias: its fields as strings, set one by one or with setNodes() as the model's nodes are */
    class AliasNode
    {
        public $fields = [];

        public function __construct($fields = [])
        {
            $this->fields = $fields;
        }

        public function __get($name)
        {
            return (string)($this->fields[$name] ?? '');
        }

        public function __set($name, $value)
        {
            $this->fields[$name] = (string)$value;
        }

        public function setNodes($values)
        {
            foreach ($values as $name => $value) {
                $this->fields[$name] = (string)$value;
            }
        }
    }

    class AliasList
    {
        public $nodes = [];
        public static $next = 100;

        public function iterateItems()
        {
            foreach ($this->nodes as $uuid => $node) {
                yield $uuid => $node;
            }
        }

        public function Add()
        {
            $uuid = sprintf('00000000-0000-4000-8000-%012d', self::$next++);
            return $this->nodes[$uuid] = new AliasNode();
        }

        public function del($uuid)
        {
            unset($this->nodes[$uuid]);
        }
    }

    /* the model: the aliases given in $given, and what a validation finds in $invalid */
    class Alias
    {
        public static $given = [];
        public static $invalid = [];
        public static $serialized = null;
        public $aliases;

        public function __construct()
        {
            $list = new AliasList();
            foreach (self::$given as $uuid => $fields) {
                $list->nodes[$uuid] = new AliasNode($fields);
            }
            $this->aliases = (object)['alias' => $list];
        }

        public function getByName($name)
        {
            foreach ($this->aliases->alias->nodes as $node) {
                if ($node->name === $name) {
                    return $node;
                }
            }
            return null;
        }

        public function performValidation()
        {
            $out = [];
            foreach (self::$invalid as $field => $message) {
                $out[] = new \OPNsense\Base\Messages\Message($message, $field);
            }
            return $out;
        }

        public function serializeToConfig()
        {
            self::$serialized = [];
            foreach ($this->aliases->alias->nodes as $uuid => $node) {
                self::$serialized[$uuid] = $node->fields;
            }
        }
    }
}

namespace OPNsense\Core {
    class Config
    {
        public static $saved = 0;

        public static function getInstance()
        {
            return new self();
        }

        public function save()
        {
            self::$saved++;
        }
    }
}

namespace {
    $root = dirname(__DIR__);
    require $root . '/src/opnsense/mvc/app/library/OPNsense/AppControl/Aliases.php';

    use OPNsense\AppControl\Aliases;
    use OPNsense\Firewall\Alias;

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

    function ours($name, $kind, $more = [])
    {
        return $more + ['enabled' => '1', 'name' => $name, 'type' => 'external', 'expire' => '3600',
            'description' => 'Application Control: ' . $kind];
    }

    $want = [
        'appcontrol_cat_Web' => ['description' => 'Application Control: category Web'],
        'appcontrol_YouTube' => ['description' => 'Application Control: YouTube'],
    ];

    /* made: External, Expire, described as the plugin's */
    Alias::$given = [];
    $model = new Alias();
    $done = Aliases::reconcile($model, '', $want, 3600);
    $web = $model->getByName('appcontrol_cat_Web');
    check($done['changes'] === ['appcontrol_cat_Web: added', 'appcontrol_YouTube: added'], 'two tables wanted, none there: both added');
    check($web !== null && $web->fields === ['name' => 'appcontrol_cat_Web', 'enabled' => '1', 'type' => 'external',
        'expire' => '3600', 'description' => 'Application Control: category Web'],
        'an alias made: switched on, External, Expire 3600, described as the plugin\'s');
    check(Aliases::reconcile(new Alias(), '', ['appcontrol_x' => []], 10)['changes'] === ['appcontrol_x: added'] &&
        (function () {
            $m = new Alias();
            Aliases::reconcile($m, '', ['appcontrol_x' => []], 10);
            return $m->getByName('appcontrol_x')->expire === '60';
        })(), 'an expiry under 60 s (the least OPNsense takes): 60');

    /* refreshed: the Expire of one already there, when the setting changed; nothing when nothing did */
    Alias::$given = ['u1' => ours('appcontrol_cat_Web', 'category Web'), 'u2' => ours('appcontrol_YouTube', 'YouTube')];
    $model = new Alias();
    $done = Aliases::reconcile($model, '', $want, 7200);
    check($done['changes'] === ['appcontrol_cat_Web: expiry 7200 s', 'appcontrol_YouTube: expiry 7200 s'] &&
        $model->getByName('appcontrol_YouTube')->expire === '7200', 'the expiry changed: both refreshed to 7200 s');
    $done = Aliases::reconcile(new Alias(), '', $want, 3600);
    check($done['changes'] === [], 'nothing changed: nothing to write');
    Alias::$given = ['u1' => ours('appcontrol_cat_Web', 'category Web', ['enabled' => '0'])];
    $model = new Alias();
    $done = Aliases::reconcile($model, '', ['appcontrol_cat_Web' => $want['appcontrol_cat_Web']], 3600);
    check($done['changes'] === ['appcontrol_cat_Web: updated'] && $model->getByName('appcontrol_cat_Web')->enabled === '1',
        'one switched off before, wanted again: switched on');

    /* the owner's alias by a name the plugin would use: left, said */
    Alias::$given = ['u3' => ['enabled' => '1', 'name' => 'appcontrol_YouTube', 'type' => 'host', 'description' => 'mine',
        'content' => '192.0.2.5']];
    $model = new Alias();
    $done = Aliases::reconcile($model, '', $want, 3600);
    check($model->getByName('appcontrol_YouTube')->type === 'host' && $model->getByName('appcontrol_YouTube')->description === 'mine',
        'an alias of the owner\'s by the name of a table: left as it is');
    check(count($done['notes']) === 1 && strpos($done['notes'][0], 'not one of this plugin') !== false &&
        $done['changes'] === ['appcontrol_cat_Web: added'], 'and said in the notes, not among the changes');

    /* removed: every alias of the plugin's; switched off where something still names it or holds its uuid */
    Alias::$given = [
        'u1' => ours('appcontrol_cat_Web', 'category Web'),
        'u2' => ours('appcontrol_YouTube', 'YouTube'),
        'u4' => ours('appcontrol_cat_Video', 'category Video'),
        'u5' => ours('appcontrol_cat_Media', 'category Media', ['enabled' => '0']),
        'u6' => ['enabled' => '1', 'name' => 'appcontrol_mine', 'type' => 'host', 'description' => 'my own list'],
        'u7' => ['enabled' => '1', 'name' => 'office', 'type' => 'host', 'description' => 'Application Control: not mine'],
    ];
    $config = '<alias uuid="u1"><name>appcontrol_cat_Web</name></alias><alias uuid="u2"><name>appcontrol_YouTube</name></alias>'
        . '<alias uuid="u4"><name>appcontrol_cat_Video</name></alias><alias uuid="u5"><name>appcontrol_cat_Media</name></alias>'
        . '<rule><destination><network>appcontrol_YouTube</network></destination></rule>'
        . '<cut_lists>u4</cut_lists><rule><source><network>appcontrol_cat_Media</network></source></rule>';
    $model = new Alias();
    $done = Aliases::reconcile($model, $config, [], 3600);
    $left = [];
    foreach ($model->aliases->alias->nodes as $node) {
        $left[$node->name] = $node->enabled;
    }
    check($left === ['appcontrol_YouTube' => '0', 'appcontrol_cat_Video' => '0', 'appcontrol_cat_Media' => '0',
        'appcontrol_mine' => '1', 'office' => '1'], 'removal: one nothing names removed; one a rule names and one XGS: Settings holds switched off; the owner\'s left');
    check($done['changes'] === ['appcontrol_cat_Web: removed',
        'appcontrol_YouTube: no longer wanted, but named elsewhere in the configuration - switched off, not removed',
        'appcontrol_cat_Video: no longer wanted, but named elsewhere in the configuration - switched off, not removed'],
        'removal: said one line each; one already off says nothing');
    check(Aliases::owned('appcontrol_cat_Web', 'Application Control: category Web') &&
        !Aliases::owned('appcontrol_cat_Web', 'my own') && !Aliases::owned('office', 'Application Control: x'),
        'an alias is the plugin\'s by its name and its description together');

    /* aliases.php, run as configd runs it: load_phalcon.php and the two scripts it asks stood in */
    $tmp = sys_get_temp_dir() . '/test-aliases.' . getmypid();
    @mkdir($tmp . '/script', 0755, true);
    $state = $tmp . '/state.json';
    file_put_contents($tmp . '/script/load_phalcon.php', '<?php
namespace OPNsense\Base\Messages { class Message { private $m; private $f;
    public function __construct($m, $f) { $this->m = $m; $this->f = $f; }
    public function getMessage() { return $this->m; } public function getField() { return $this->f; } } }
namespace OPNsense\Firewall {
    class AliasNode { public $fields = []; public function __construct($f = []) { $this->fields = $f; }
        public function __get($n) { return (string)($this->fields[$n] ?? ""); }
        public function __set($n, $v) { $this->fields[$n] = (string)$v; }
        public function setNodes($v) { foreach ($v as $k => $x) { $this->fields[$k] = (string)$x; } } }
    class AliasList { public $nodes = []; public function iterateItems() { foreach ($this->nodes as $u => $n) { yield $u => $n; } }
        public function Add() { $u = "u" . (count($this->nodes) + 100); return $this->nodes[$u] = new AliasNode(); }
        public function del($u) { unset($this->nodes[$u]); } }
    class Alias { public $aliases;
        public function __construct() { $l = new AliasList(); $s = json_decode((string)@file_get_contents(getenv("STATE")), true);
            foreach (($s["aliases"] ?? []) as $u => $f) { $l->nodes[$u] = new AliasNode($f); } $this->aliases = (object)["alias" => $l]; }
        public function getByName($n) { foreach ($this->aliases->alias->nodes as $x) { if ($x->name === $n) { return $x; } } return null; }
        public function performValidation() { $bad = getenv("INVALID"); return $bad ? [new \OPNsense\Base\Messages\Message($bad, "aliases.alias.u1.name")] : []; }
        public function serializeToConfig() { $s = json_decode((string)@file_get_contents(getenv("STATE")), true) ?: [];
            $s["aliases"] = []; foreach ($this->aliases->alias->nodes as $u => $n) { $s["aliases"][$u] = $n->fields; }
            $s["serialized"] = ($s["serialized"] ?? 0) + 1; file_put_contents(getenv("STATE"), json_encode($s)); } } }
namespace OPNsense\Core { class Config { public static function getInstance() { return new self(); }
    public function save() { $s = json_decode((string)file_get_contents(getenv("STATE")), true);
        $s["saved"] = ($s["saved"] ?? 0) + 1; file_put_contents(getenv("STATE"), json_encode($s)); } } }
namespace { require "' . $root . '/src/opnsense/mvc/app/library/OPNsense/AppControl/Aliases.php"; }
');
    copy($root . '/src/opnsense/scripts/appcontrol/aliases.php', $tmp . '/aliases.php');
    file_put_contents($tmp . '/apps.py', "#!/bin/sh\necho '{\"installed\": true}'\n");
    file_put_contents($tmp . '/tables.py', "#!/bin/sh\n[ -n \"\$NAMES\" ] || exit 1\necho \"\$NAMES\"\nexit \${STATUS:-0}\n");
    chmod($tmp . '/apps.py', 0755);
    chmod($tmp . '/tables.py', 0755);

    function run_script($tmp, $state, $env, $args = '')
    {
        $prefix = '';
        foreach ($env as $k => $v) {
            $prefix .= $k . '=' . escapeshellarg($v) . ' ';
        }
        $out = shell_exec($prefix . 'STATE=' . escapeshellarg($state) . ' ' . escapeshellarg(PHP_BINARY) .
            ' -d include_path=' . escapeshellarg($tmp) . ' ' . escapeshellarg($tmp . '/aliases.php') . ' ' . $args);
        return [json_decode((string)$out, true), json_decode((string)@file_get_contents($state), true)];
    }

    $names = json_encode(['ttl' => 3600, 'classify' => true, 'aliases' => $want]);
    file_put_contents($state, json_encode(['aliases' => []]));
    [$out, $saved] = run_script($tmp, $state, ['NAMES' => $names]);
    check(($out['status'] ?? '') === 'ok' && count($out['changes'] ?? []) === 2 && ($saved['saved'] ?? 0) === 1 &&
        count($saved['aliases'] ?? []) === 2, 'aliases.php: the tables wanted made, the configuration saved once');
    [$out, $saved] = run_script($tmp, $state, ['NAMES' => $names]);
    check(($out['status'] ?? '') === 'ok' && ($out['changes'] ?? null) === [] && ($saved['saved'] ?? 0) === 1,
        'aliases.php again, nothing changed: nothing saved');
    [$out, $saved] = run_script($tmp, $state, ['NAMES' => $names, 'INVALID' => 'An alias with this name already exists.']);
    check(($out['status'] ?? '') === 'failed' && in_array('aliases.alias.u1.name: An alias with this name already exists.',
        $out['errors'] ?? [], true) && ($saved['saved'] ?? 0) === 1, 'aliases.php, the model refusing: said, nothing saved');
    file_put_contents($state, json_encode(['aliases' => $saved['aliases']]));
    [$out, $saved] = run_script($tmp, $state, []);
    check(($out['status'] ?? '') === 'failed' && empty($saved['saved']) && count($saved['aliases']) === 2,
        'aliases.php, the names not readable: said, no alias touched');
    [$out, $saved] = run_script($tmp, $state, ['NAMES' => $names, 'STATUS' => '1']);
    check(($out['status'] ?? '') === 'failed' && empty($saved['saved']) && count($saved['aliases']) === 2,
        'aliases.php, tables.py printing names but failing: said, no alias touched');
    [$out, $saved] = run_script($tmp, $state, [], '--remove');
    check(($out['status'] ?? '') === 'ok' && ($saved['aliases'] ?? null) === [] && ($saved['saved'] ?? 0) === 1,
        'aliases.php --remove: every alias of the plugin\'s taken out, without asking for the names');

    foreach (glob($tmp . '/script/*') as $f) {
        unlink($f);
    }
    rmdir($tmp . '/script');
    foreach (glob($tmp . '/*') as $f) {
        unlink($f);
    }
    rmdir($tmp);

    echo $failed ? "$failed of $checks checks failed\n" : "$checks checks passed\n";
    exit($failed ? 1 : 0);
}
