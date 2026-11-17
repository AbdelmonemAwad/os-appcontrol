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
 * aliases gone and the classifier, in that order; the classifier stopped when classifying is off;
 * nothing after the aliases when they could not be written; nothing at all for a GET.
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

    use OPNsense\AppControl\Api\ServiceController;
    use OPNsense\AppControl\AppControl;
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
        'appcontrol flush' => json_encode(['emptied' => []])];
    Backend::$asked = [];
    AppControl::$classify = '1';
    $result = (new ServiceController())->reconfigureAction();
    check(Backend::$asked === ['appcontrol apply', 'filter reload skip_alias', 'cron restart', 'appcontrol flush',
        'appcontrol restart'], 'Apply, classifying on: the aliases, the filter, cron, the tables of aliases gone, the classifier started again');
    check(($result['status'] ?? '') === 'ok' && $result['classify'] === true && $result['changes'] === ['appcontrol_cat_Web: added'],
        'Apply: what changed passed on to the page');
    AppControl::$classify = '0';
    Backend::$asked = [];
    (new ServiceController())->reconfigureAction();
    check(end(Backend::$asked) === 'appcontrol stop', 'Apply, classifying off: the classifier stopped');
    Backend::$answers = ['appcontrol apply' => json_encode(['status' => 'failed', 'errors' => ['refused']])];
    Backend::$asked = [];
    $result = (new ServiceController())->reconfigureAction();
    check(Backend::$asked === ['appcontrol apply'] && $result['errors'] === ['refused'],
        'Apply, the aliases not written: nothing more done, the reason passed on');
    Backend::$answers = [];
    Backend::$asked = [];
    $result = (new ServiceController())->reconfigureAction();
    check(Backend::$asked === ['appcontrol apply'] && $result['status'] === 'failed', 'Apply, no answer: failed, nothing more done');

    echo $failed ? "$failed of $checks checks failed\n" : "$checks checks passed\n";
    exit($failed ? 1 : 0);
}
