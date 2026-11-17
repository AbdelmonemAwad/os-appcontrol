<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 */

namespace OPNsense\AppControl\Api;

use OPNsense\AppControl\AppControl;
use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

class ServiceController extends ApiControllerBase
{
    private function json($action)
    {
        $result = json_decode((string)(new Backend())->configdRun('appcontrol ' . $action), true);
        return is_array($result) ? $result : ['error' => gettext('No answer could be read.')];
    }

    public function statusAction()
    {
        return $this->json('status');
    }

    /**
     * the Applications tab's grid: each application nDPI named since the classifier started, and each
     * one chosen in Settings, with its category and its table
     */
    public function searchAppsAction()
    {
        $rows = [];
        foreach (($this->json('status')['apps'] ?? []) as $app) {
            if (!is_array($app)) {
                continue;
            }
            $rows[] = [
                'name' => (string)($app['name'] ?? ''),
                'category' => (string)($app['category'] ?? ''),
                'protocols' => implode(', ', array_map('strval', (array)($app['protocols'] ?? []))),
                'named' => (int)($app['named'] ?? 0),
                'guessed' => (int)($app['guessed'] ?? 0),
                'last' => isset($app['last']) ? (int)$app['last'] : null,
                'table' => (string)($app['table'] ?? ''),
                'chosen' => !empty($app['chosen']),
                'entries' => isset($app['entries']) ? (int)$app['entries'] : null,
            ];
        }
        return $this->searchRecordsetBase($rows, ['name', 'category', 'protocols', 'table'], 'name');
    }

    /**
     * the category tables: one alias each, and the addresses pf holds in it
     */
    public function searchCategoriesAction()
    {
        $rows = [];
        foreach (($this->json('status')['categories'] ?? []) as $category) {
            if (!is_array($category)) {
                continue;
            }
            $rows[] = [
                'table' => (string)($category['table'] ?? ''),
                'name' => (string)($category['name'] ?? ''),
                'entries' => isset($category['entries']) ? (int)$category['entries'] : null,
            ];
        }
        return $this->searchRecordsetBase($rows, ['table', 'name'], 'name');
    }

    /**
     * the Unknown tab's grid: the connections nDPI did not name, by server, latest first
     */
    public function searchUnknownAction()
    {
        $rows = [];
        foreach (($this->json('unknown')['rows'] ?? []) as $row) {
            if (!is_array($row)) {
                continue;
            }
            $rows[] = [
                'id' => (string)($row['id'] ?? ''),
                'kind' => (string)($row['kind'] ?? ''),
                'name' => (string)($row['name'] ?? ''),
                'proto' => (int)($row['proto'] ?? 0),
                'server' => (string)($row['server'] ?? ''),
                'port' => (int)($row['port'] ?? 0),
                'server_name' => (string)($row['server_name'] ?? ''),
                'ja4' => (string)($row['ja4'] ?? ''),
                'connections' => (int)($row['connections'] ?? 0),
                'last' => isset($row['last']) ? (int)$row['last'] : null,
                'interfaces' => implode(', ', array_map('strval', (array)($row['interfaces'] ?? []))),
            ];
        }
        return $this->searchRecordsetBase($rows, ['name', 'server', 'server_name', 'ja4']);
    }

    /**
     * the settings just saved put into the firewall: the aliases made to say what they say (aliases.php,
     * which reads the installed nDPI again first), the filter reloaded so pf holds their tables, cron so
     * their Expire runs, the tables of aliases gone emptied, then the classifier started again - or
     * stopped, when classifying is off. When the aliases could not be written nothing more is done,
     * except that a classifier turned off is stopped all the same: off means it does not run.
     */
    public function reconfigureAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed'];
        }
        $backend = new Backend();
        $result = json_decode((string)$backend->configdRun('appcontrol apply'), true);
        if (!is_array($result) || ($result['status'] ?? '') !== 'ok') {
            $result = is_array($result) ? $result : ['status' => 'failed', 'errors' => [gettext('No answer could be read.')]];
            if (!$this->classifying()) {
                $backend->configdRun('appcontrol stop');
                $result['classify'] = false;
            }
            return $result;
        }
        $backend->configdRun('filter reload skip_alias');
        $backend->configdRun('cron restart');
        $result['emptied'] = json_decode((string)$backend->configdRun('appcontrol flush'), true);
        $on = $this->classifying();
        $backend->configdRun($on ? 'appcontrol restart' : 'appcontrol stop');
        $result['classify'] = $on;
        return $result;
    }

    /**
     * whether classifying is on in the settings just saved
     */
    private function classifying()
    {
        return (string)(new AppControl())->general->classify === '1';
    }
}
