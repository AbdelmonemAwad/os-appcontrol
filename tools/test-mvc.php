<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 *
 * The page's API (Api/ServiceController), run as OPNsense runs it, with stand-ins for what it reaches of
 * OPNsense's MVC: ApiControllerBase - the request, and the grids' search, which here hands the rows
 * back - configd (Backend), and the plugin's model, whose classify it reads.
 *
 * What is checked: the status script's answer passed on, and one that cannot be read said; the
 * Applications and Unknown grids' rows; and Apply - the aliases, then the filter, cron, the tables of
 * aliases gone, the Suricata rules of the Rules tab - and ids reload when they changed - and the
 * classifier, in that order; the classifier stopped when classifying is off; nothing after the aliases
 * when they could not be written, but the classifier stopped and the Suricata rules taken away all the
 * same when classifying is off; nothing at all for a GET. And the Rules tab (Api/SettingsController, with
 * stand-ins for ApiMutableModelControllerBase, config.xml and the Alias model): its grid's rows with what
 * each rule does now, its action and source as stored; each of its calls on the model's rules.rule; and
 * the source selector's networks and aliases.
 *
 *   php tools/test-mvc.php
 */

namespace OPNsense\Base {
    class ApiControllerBase
    {
        public $request;

        public function __construct()
        {
            $this->request = new class {
                public $post = true;

                public function isPost()
                {
                    return $this->post;
                }
            };
        }

        protected function searchRecordsetBase($records, $fields = null, $defaultSort = null)
        {
            return ['rows' => $records, 'fields' => $fields, 'sort' => $defaultSort];
        }
    }

    /* the model's grid calls, written down; searchBase gives the rows set here, as OPNsense's gives the model's */
    class ApiMutableModelControllerBase extends ApiControllerBase
    {
        public static $rows = [];
        public static $calls = [];
        public static $model = null;

        protected function searchBase($path, $fields = null)
        {
            self::$calls[] = ['searchBase', $path, $fields];
            return ['rows' => self::$rows, 'rowCount' => count(self::$rows), 'total' => count(self::$rows), 'current' => 1];
        }

        protected function getModel()
        {
            return self::$model;
        }

        public function __call($name, $args)
        {
            self::$calls[] = array_merge([$name], $args);
            return ['result' => $name];
        }
    }
}

namespace OPNsense\Core {
    class Backend
    {
        public static $answers = [];
        public static $asked = [];

        public function configdRun($event, $detach = false)
        {
            self::$asked[] = $event;
            return self::$answers[$event] ?? null;
        }
    }

    /* config.xml's interfaces, as OPNsense's Config object gives them: name => node with its descr */
    class Config
    {
        public static $interfaces = [];

        public static function getInstance()
        {
            return new self();
        }

        public function object()
        {
            $nodes = [];
            foreach (self::$interfaces as $name => $descr) {
                $nodes[$name] = $descr === null ? (object)[] : (object)['descr' => $descr];
            }
            return (object)['interfaces' => new class ($nodes) {
                private $nodes;

                public function __construct($nodes)
                {
                    $this->nodes = $nodes;
                }

                public function children()
                {
                    return $this->nodes;
                }
            }];
        }
    }
}

namespace OPNsense\Firewall {
    class Alias
    {
        public static $given = [];
        public $aliases;

        public function __construct()
        {
            $items = array_map(function ($a) {
                return (object)['name' => $a[0], 'type' => $a[1]];
            }, self::$given);
            $this->aliases = (object)['alias' => new class ($items) {
                private $items;

                public function __construct($items)
                {
                    $this->items = $items;
                }

                public function iterateItems()
                {
                    foreach ($this->items as $i => $item) {
                        yield 'uuid-' . $i => $item;
                    }
                }
            }];
        }
    }
}

namespace OPNsense\AppControl {
    class AppControl
    {
        public static $classify = '1';
        public $general;

        public function __construct()
        {
            $this->general = (object)['classify' => self::$classify];
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

    require dirname(__DIR__) . '/src/opnsense/mvc/app/controllers/OPNsense/AppControl/Api/ServiceController.php';
    require dirname(__DIR__) . '/src/opnsense/mvc/app/controllers/OPNsense/AppControl/Api/SettingsController.php';
    require dirname(__DIR__) . '/src/opnsense/mvc/app/library/OPNsense/AppControl/Rules.php';

    use OPNsense\AppControl\Api\ServiceController;
    use OPNsense\AppControl\Api\SettingsController;
    use OPNsense\AppControl\AppControl;
    use OPNsense\Base\ApiMutableModelControllerBase;
    use OPNsense\Core\Backend;

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

    /* status: the script's answer, or that it could not be read */
    Backend::$answers = ['appcontrol status' => json_encode(['running' => true, 'totals' => ['named' => 3]])];
    check((new ServiceController())->statusAction() === ['running' => true, 'totals' => ['named' => 3]],
        'status: the status script\'s answer passed on');
    foreach (['', 'not json', '"a string"', null] as $bad) {
        Backend::$answers = ['appcontrol status' => $bad];
        check((new ServiceController())->statusAction() === ['error' => 'No answer could be read.'],
            'status: configd answering ' . json_encode($bad) . ': could not be read');
    }

    /* the grids */
    Backend::$answers = ['appcontrol status' => json_encode(['apps' => [
        ['name' => 'YouTube', 'category' => 'Media', 'protocols' => ['TLS', 'QUIC'], 'named' => 3, 'guessed' => 1,
            'last' => 1794926400, 'table' => 'appcontrol_YouTube', 'chosen' => true, 'entries' => 2],
        'not a row',
        ['name' => 'DNS', 'named' => 5],
    ], 'categories' => [['table' => 'appcontrol_cat_Web', 'name' => 'Web', 'entries' => 7]]])];
    $grid = (new ServiceController())->searchAppsAction();
    check(count($grid['rows']) === 2 && $grid['rows'][0]['protocols'] === 'TLS, QUIC' && $grid['rows'][0]['entries'] === 2 &&
        $grid['rows'][1]['table'] === '' && $grid['rows'][1]['entries'] === null && $grid['rows'][1]['last'] === null,
        'Applications: each application\'s row, a row that is none left out, what is missing empty');
    check($grid['sort'] === 'name' && $grid['fields'] === ['name', 'category', 'protocols', 'table'],
        'Applications: searched by name, category, protocol and table, by name');
    $grid = (new ServiceController())->searchCategoriesAction();
    check($grid['rows'] === [['table' => 'appcontrol_cat_Web', 'name' => 'Web', 'entries' => 7]], 'Categories: each table');
    Backend::$answers = ['appcontrol unknown' => json_encode(['rows' => [
        ['id' => 'k', 'kind' => 'no_app', 'name' => 'TLS', 'proto' => 6, 'server' => '198.51.100.20', 'port' => 443,
            'server_name' => 'api.example.com', 'ja4' => 't13d1516h2_8daaf6152771_e5627efa2ab1', 'connections' => 2,
            'last' => 1794926400, 'interfaces' => ['lan', 'opt1']]]])];
    $grid = (new ServiceController())->searchUnknownAction();
    check(count($grid['rows']) === 1 && $grid['rows'][0]['interfaces'] === 'lan, opt1' && $grid['rows'][0]['port'] === 443 &&
        $grid['rows'][0]['ja4'] === 't13d1516h2_8daaf6152771_e5627efa2ab1', 'Unknown: each row, its interfaces joined');

    /* Apply */
    $controller = new ServiceController();
    $controller->request->post = false;
    Backend::$asked = [];
    check($controller->reconfigureAction() === ['status' => 'failed'] && Backend::$asked === [], 'Apply by GET: refused, nothing asked');
    Backend::$answers = ['appcontrol apply' => json_encode(['status' => 'ok', 'changes' => ['appcontrol_cat_Web: added']]),
        'appcontrol flush' => json_encode(['killed' => ['appcontrol_cat_Gone'], 'errors' => []]),
        'appcontrol suricata' => json_encode(['status' => 'ok', 'changed' => false, 'lines' => 37, 'errors' => []]),
        'appcontrol release' => json_encode(['released' => 2, 'kept' => 1, 'errors' => []])];
    Backend::$asked = [];
    AppControl::$classify = '1';
    $result = (new ServiceController())->reconfigureAction();
    check(Backend::$asked === ['appcontrol apply', 'filter reload skip_alias', 'cron restart', 'appcontrol flush',
        'appcontrol suricata', 'appcontrol reload', 'appcontrol release'], 'Apply, classifying on: the aliases, the filter and ' .
        'its block rules, cron, the tables of aliases gone, the Suricata rules of the Rules tab - unchanged, so no reload of the ' .
        'Intrusion Detection - the classifier\'s settings read again (not a restart, which forgets what it remembers), then ' .
        'what was dropped in hardware for an application no longer blocked handed back');
    check(($result['status'] ?? '') === 'ok' && $result['classify'] === true && $result['changes'] === ['appcontrol_cat_Web: added'],
        'Apply: what changed passed on to the page');
    check(($result['gone_tables']['killed'] ?? null) === ['appcontrol_cat_Gone'],
        'Apply: the tables of aliases gone, taken out of pf, passed on to the page');
    check(($result['released']['released'] ?? null) === 2, 'Apply: how many were handed back from hardware, passed on to the page');
    check(($result['suricata']['lines'] ?? null) === 37, 'Apply: what the Suricata rules came to, passed on to the page');
    Backend::$answers['appcontrol suricata'] = json_encode(['status' => 'ok', 'changed' => true, 'lines' => 38]);
    Backend::$asked = [];
    (new ServiceController())->reconfigureAction();
    check(array_slice(Backend::$asked, 4, 2) === ['appcontrol suricata', 'ids reload'],
        'Apply, the Suricata rules changed: the Intrusion Detection\'s rules installed again and Suricata told (ids reload)');
    Backend::$answers['appcontrol suricata'] = 'not json';
    $result = (new ServiceController())->reconfigureAction();
    check($result['suricata'] === ['status' => 'failed', 'changed' => false, 'errors' => ['No answer could be read.']],
        'Apply, the Suricata rules\' answer not to be read: said, no reload');
    AppControl::$classify = '0';
    Backend::$answers['appcontrol suricata'] = json_encode(['status' => 'ok', 'changed' => true, 'lines' => 0]);
    Backend::$asked = [];
    (new ServiceController())->reconfigureAction();
    check(array_slice(Backend::$asked, -4) === ['appcontrol suricata', 'ids reload', 'appcontrol stop', 'appcontrol release'],
        'Apply, classifying off: the Suricata rules taken away, the classifier stopped, then everything dropped in hardware ' .
        'handed back - no alias, nothing blocked');
    AppControl::$classify = '1';
    Backend::$answers = ['appcontrol apply' => json_encode(['status' => 'failed', 'errors' => ['refused']])];
    Backend::$asked = [];
    $result = (new ServiceController())->reconfigureAction();
    check(Backend::$asked === ['appcontrol apply'] && $result['errors'] === ['refused'],
        'Apply, classifying on, the aliases not written: nothing more done, the reason passed on');
    Backend::$answers = [];
    Backend::$asked = [];
    $result = (new ServiceController())->reconfigureAction();
    check(Backend::$asked === ['appcontrol apply'] && $result['status'] === 'failed',
        'Apply, classifying on, no answer: failed, nothing more done');
    AppControl::$classify = '0';
    Backend::$answers = ['appcontrol apply' => json_encode(['status' => 'failed', 'errors' => ['refused']]),
        'appcontrol suricata' => json_encode(['status' => 'ok', 'changed' => true])];
    Backend::$asked = [];
    $result = (new ServiceController())->reconfigureAction();
    check(Backend::$asked === ['appcontrol apply', 'appcontrol stop', 'appcontrol suricata', 'ids reload'] &&
        $result['errors'] === ['refused'] && $result['classify'] === false, 'Apply, classifying off, the aliases not written: ' .
        'the classifier stopped and the Suricata rules taken away all the same, the reason passed on');
    Backend::$answers = [];
    Backend::$asked = [];
    $result = (new ServiceController())->reconfigureAction();
    check(Backend::$asked === ['appcontrol apply', 'appcontrol stop', 'appcontrol suricata'] && $result['status'] === 'failed',
        'Apply, classifying off, no answer: failed, the classifier stopped all the same');

    /* the Rules tab: what each rule does now */
    Backend::$answers = ['appcontrol rules' => json_encode(['rules' => ['u1' => ['state' => 'active']], 'ids' => ['enabled' => true]])];
    check((new ServiceController())->rulesAction() === ['rules' => ['u1' => ['state' => 'active']], 'ids' => ['enabled' => true]],
        'the Rules tab\'s state: status.py rules\' answer passed on');

    /* the Rules tab's grid and its calls on the model */
    ApiMutableModelControllerBase::$rows = [
        ['uuid' => 'u1', 'enabled' => '1', 'action' => 'Block', 'source' => 'GUEST net', 'source_not' => '0', 'app' => 'YouTube',
            'description' => 'guests'],
        ['uuid' => 'u2', 'enabled' => '1', 'action' => 'Alert', 'source' => 'any', 'source_not' => '0', 'app' => 'SSH',
            'description' => ''],
    ];
    ApiMutableModelControllerBase::$model = (object)['rules' => (object)['rule' => new class {
        public function iterateItems()
        {
            yield 'u1' => (object)['action' => 'block', 'source' => 'opt2'];
            yield 'u2' => (object)['action' => 'alert', 'source' => 'any'];
        }
    }]];
    Backend::$answers = ['appcontrol rules' => json_encode(['rules' => [
        'u1' => ['state' => 'active', 'cut' => 4, 'suricata' => ['lines' => 36, 'reason' => null]],
        'u2' => ['state' => 'pending', 'cut' => 0, 'suricata' => ['lines' => 0, 'reason' => 'no_match']]]])];
    ApiMutableModelControllerBase::$calls = [];
    $grid = (new SettingsController())->searchRuleAction();
    check(ApiMutableModelControllerBase::$calls[0] === ['searchBase', 'rules.rule', ['enabled', 'action', 'source', 'source_not',
        'app', 'description']], 'the Rules grid: the model\'s rules.rule, its columns');
    check(array_map(function ($r) {
        return [$r['uuid'], $r['action_key'], $r['source_key'], $r['state'], $r['cut'], $r['suricata_lines'], $r['suricata_reason']];
    }, $grid['rows']) === [['u1', 'block', 'opt2', 'active', 4, 36, ''], ['u2', 'alert', 'any', 'pending', 0, 0, 'no_match']],
        'the Rules grid: each rule\'s action and source as stored, its state, the connections cut for it, its Suricata lines or why none');
    Backend::$answers = [];
    $grid = (new SettingsController())->searchRuleAction();
    check($grid['rows'][0]['state'] === '' && $grid['rows'][0]['cut'] === 0 && $grid['rows'][0]['suricata_reason'] === '',
        'the Rules grid, what the rules do now not to be read: the rules listed all the same, nothing said of them');
    ApiMutableModelControllerBase::$calls = [];
    $settings = new SettingsController();
    $settings->getRuleAction('u1');
    $settings->addRuleAction();
    $settings->setRuleAction('u1');
    $settings->delRuleAction('u1');
    $settings->toggleRuleAction('u1', '0');
    check(ApiMutableModelControllerBase::$calls === [['getBase', 'rule', 'rules.rule', 'u1'], ['addBase', 'rule', 'rules.rule'],
        ['setBase', 'rule', 'rules.rule', 'u1'], ['delBase', 'rules.rule', 'u1'], ['toggleBase', 'rules.rule', 'u1', '0']],
        'the Rules grid\'s calls: get, add, set, del and toggle, each on rules.rule, as the dialog posts it under "rule"');

    /* the source selector */
    \OPNsense\Core\Config::$interfaces = ['wan' => 'WAN', 'lan' => 'LAN', 'opt2' => 'GUEST', 'opt3' => null];
    \OPNsense\Firewall\Alias::$given = [['Teachers', 'host'], ['web_ports', 'port'], ['appcontrol_YouTube', 'external'],
        ['Countries', 'geoip'], ['__lan_network', 'internal']];
    $options = (new SettingsController())->listNetworkSelectOptionsAction();
    check($options === [
        'single' => ['label' => 'Single host or Network'],
        'aliases' => ['label' => 'Aliases', 'items' => ['Countries' => 'Countries', 'Teachers' => 'Teachers']],
        'networks' => ['label' => 'Networks', 'items' => ['any' => 'any', 'opt2' => 'GUEST network', 'lan' => 'LAN network',
            'opt3' => 'OPT3 network', 'wan' => 'WAN network']],
    ], 'the source selector: an address by hand; any and each interface\'s network, by its description; the aliases of ' .
        'addresses - not those of ports, OPNsense\'s internal ones, nor this plugin\'s tables of servers; not the firewall itself');

    echo $failed ? "$failed of $checks checks failed\n" : "$checks checks passed\n";
    exit($failed ? 1 : 0);
}
