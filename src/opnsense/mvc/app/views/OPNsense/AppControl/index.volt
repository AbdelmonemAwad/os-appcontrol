{#
 # SPDX-License-Identifier: BSD-2-Clause
 # Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 #
 # Firewall: Application Control (XGS: Application Control when os-xgs-npu is installed) - which
 # application each connection belongs to, by nDPI, the tables of servers that follow from it, the
 # applications blocked, and the connections nDPI did not name.
 #}

<style>
    /* KIT-CSS-BEGIN */
    .xgs-cards { display: flex; flex-wrap: wrap; gap: 12px; padding: 15px; }
    .xgs-cards.xgs-top { padding: 0 0 15px; }
    .xgs-card { flex: 1 1 200px; min-width: 190px; border: 1px solid rgba(128, 128, 128, 0.25);
                border-inline-start: 4px solid #9e9e9e; border-radius: 3px; padding: 10px 14px;
                background-color: rgba(128, 128, 128, 0.04); }
    .xgs-card.ok { border-inline-start-color: #5cb85c; }
    .xgs-card.warn { border-inline-start-color: #f0ad4e; }
    .xgs-card.bad { border-inline-start-color: #d9534f; }
    .xgs-card .k { font-size: 11px; text-transform: uppercase; letter-spacing: .04em; opacity: 0.6; }
    .xgs-card .v { font-size: 19px; font-weight: 600; line-height: 1.3; margin: 2px 0; }
    .xgs-card .s { font-size: 12px; opacity: 0.7; }
    .xgs-card .fa { opacity: 0.35; float: inline-end; font-size: 18px; margin-top: 2px; }
    .xgs-head { padding-top: 5px; padding-bottom: 5px; font-size: 16px; }
    /* KIT-CSS-END */
    /* A grid whose columns fill the width shows a one-pixel sideways bar when no vertical one takes
       the difference; wide screens never need to scroll it sideways. */
    @media (min-width: 768px) {
        #grid-apps .tabulator-tableholder, #grid-categories .tabulator-tableholder,
        #grid-unknown .tabulator-tableholder { overflow-x: hidden; }
    }
    .ac-note { padding: 0 15px 10px; }
</style>

<script>
    $(document).ready(function () {
        /* KIT-JS-BEGIN */
        /* A string as OPNsense's API and Volt's lang._() hand it over - escaped - made plain for .text(). */
        function plain(value) {
            return $('<textarea/>').html(value === null || value === undefined ? '' : String(value)).text();
        }

        /* One card: cls '' (grey, no judgement), 'ok', 'warn' or 'bad'; icon a Font Awesome name. */
        function card(cls, icon, key, value, sub) {
            return $('<div class="xgs-card"/>').addClass(cls)
                .append($('<i class="fa"/>').addClass(icon))
                .append($('<div class="k"/>').text(plain(key)))
                .append($('<div class="v"/>').text(plain(value)))
                .append($('<div class="s"/>').text(plain(sub || ' ')));
        }

        /* Until the first reading: the same cards, their keys, and an ellipsis for every value. */
        function cards_wait(target, keys) {
            $(target).empty();
            $.each(keys, function (i, key) {
                $(target).append(card('', 'fa-ellipsis-h', key, '…', ''));
            });
        }

        /* The selected tab kept in the address, as on OPNsense's own tabbed pages. */
        function keep_tab() {
            if (window.location.hash !== '') {
                $('a[href="' + window.location.hash + '"]').tab('show');
            }
            $('.nav-tabs a').on('shown.bs.tab', function (e) {
                history.pushState(null, null, e.target.hash);
            });
        }
        /* KIT-JS-END */

        /* AC-CATEGORIES-BEGIN */
        /* nDPI's categories as the page shows them, the English as nDPI writes it - this map is made
           from categories.json by tools/gen-data-strings.py, which checks it is current. */
        const category_text = {
            'Media': "{{ lang._('Media') }}",
            'VPN': "{{ lang._('VPN') }}",
            'Email': "{{ lang._('Email') }}",
            'DataTransfer': "{{ lang._('DataTransfer') }}",
            'Web': "{{ lang._('Web') }}",
            'SocialNetwork': "{{ lang._('SocialNetwork') }}",
            'Download': "{{ lang._('Download') }}",
            'Game': "{{ lang._('Game') }}",
            'Chat': "{{ lang._('Chat') }}",
            'VoIP': "{{ lang._('VoIP') }}",
            'Database': "{{ lang._('Database') }}",
            'RemoteAccess': "{{ lang._('RemoteAccess') }}",
            'Cloud': "{{ lang._('Cloud') }}",
            'Network': "{{ lang._('Network') }}",
            'Collaborative': "{{ lang._('Collaborative') }}",
            'RPC': "{{ lang._('RPC') }}",
            'Streaming': "{{ lang._('Streaming') }}",
            'System': "{{ lang._('System') }}",
            'SoftwareUpdate': "{{ lang._('SoftwareUpdate') }}",
            'Music': "{{ lang._('Music') }}",
            'Video': "{{ lang._('Video') }}",
            'Shopping': "{{ lang._('Shopping') }}",
            'Productivity': "{{ lang._('Productivity') }}",
            'FileSharing': "{{ lang._('FileSharing') }}",
            'ConnCheck': "{{ lang._('ConnCheck') }}",
            'IoT-Scada': "{{ lang._('IoT-Scada') }}",
            'Cybersecurity': "{{ lang._('Cybersecurity') }}",
            'AdultContent': "{{ lang._('AdultContent') }}",
            'Mining': "{{ lang._('Mining') }}",
            'Malware': "{{ lang._('Malware') }}",
            'Advertisement': "{{ lang._('Advertisement') }}",
            'Banned_Site': "{{ lang._('Banned_Site') }}",
            'Site_Unavailable': "{{ lang._('Site_Unavailable') }}",
            'Allowed_Site': "{{ lang._('Allowed_Site') }}",
            'Antimalware': "{{ lang._('Antimalware') }}",
            'Crypto_Currency': "{{ lang._('Crypto_Currency') }}",
            'Gambling': "{{ lang._('Gambling') }}",
            'Health': "{{ lang._('Health') }}",
            'ArtifIntelligence': "{{ lang._('ArtifIntelligence') }}",
            'Finance': "{{ lang._('Finance') }}",
            'News': "{{ lang._('News') }}",
            'Sport': "{{ lang._('Sport') }}",
            'Business': "{{ lang._('Business') }}",
            'Internet': "{{ lang._('Internet') }}",
            'Blockchain_Crypto': "{{ lang._('Blockchain_Crypto') }}",
            'Blog_Forum': "{{ lang._('Blog_Forum') }}",
            'Government': "{{ lang._('Government') }}",
            'Education': "{{ lang._('Education') }}",
            'CDN_Proxy': "{{ lang._('CDN_Proxy') }}",
            'Hw_Sw': "{{ lang._('Hw_Sw') }}",
            'Dating': "{{ lang._('Dating') }}",
            'Travel': "{{ lang._('Travel') }}",
            'Food': "{{ lang._('Food') }}",
            'Bots': "{{ lang._('Bots') }}",
            'Scanners': "{{ lang._('Scanners') }}",
            'Hosting': "{{ lang._('Hosting') }}",
            'Art': "{{ lang._('Art') }}",
            'Fashion': "{{ lang._('Fashion') }}",
            'Books': "{{ lang._('Books') }}",
            'Science': "{{ lang._('Science') }}",
            'Maps_Navigation': "{{ lang._('Maps_Navigation') }}",
            'Login_Portal': "{{ lang._('Login_Portal') }}",
            'Legal': "{{ lang._('Legal') }}",
            'Environmental_Services': "{{ lang._('Environmental_Services') }}",
            'Culture': "{{ lang._('Culture') }}",
            'Housing': "{{ lang._('Housing') }}",
            'Telecommunication': "{{ lang._('Telecommunication') }}",
            'Transportation': "{{ lang._('Transportation') }}",
            'Design': "{{ lang._('Design') }}",
            'Employment': "{{ lang._('Employment') }}",
            'Events': "{{ lang._('Events') }}",
            'Weather': "{{ lang._('Weather') }}",
            'Lifestyle': "{{ lang._('Lifestyle') }}",
            'Real_Estate': "{{ lang._('Real_Estate') }}",
            'Security': "{{ lang._('Security') }}",
            'Environment': "{{ lang._('Environment') }}",
            'Hobby': "{{ lang._('Hobby') }}",
            'Computer_Science': "{{ lang._('Computer_Science') }}",
            'Construction': "{{ lang._('Construction') }}",
            'Engineering': "{{ lang._('Engineering') }}",
            'Religion': "{{ lang._('Religion') }}",
            'Entertainment': "{{ lang._('Entertainment') }}",
            'Agriculture': "{{ lang._('Agriculture') }}",
            'Technology': "{{ lang._('Technology') }}",
            'Beauty': "{{ lang._('Beauty') }}",
            'History': "{{ lang._('History') }}",
            'Politics': "{{ lang._('Politics') }}",
            'Vehicles': "{{ lang._('Vehicles') }}",
            'Search_Engine': "{{ lang._('Search_Engine') }}",
            'Children': "{{ lang._('Children') }}",
            'Violence': "{{ lang._('Violence') }}",
            'Drugs': "{{ lang._('Drugs') }}",
            'Weapons': "{{ lang._('Weapons') }}"
        };
        /* AC-CATEGORIES-END */

        function count(n) {
            return n === null || n === undefined || n === '' ? '-' : Number(n).toLocaleString();
        }

        function when(ts) {
            return ts ? new Date(ts * 1000).toLocaleString() : '-';
        }

        function category(name) {
            return name ? (category_text[name] || name) : '-';
        }

        const protocols = {1: 'ICMP', 6: 'TCP', 17: 'UDP', 58: 'ICMPv6'};
        const kinds = {
            'unknown': "{{ lang._('not named') }}",
            'guess': "{{ lang._('guessed') }}",
            'no_app': "{{ lang._('no application') }}"
        };

        /*
         * Four cards: the applications nDPI named since the classifier started, the connections it
         * named by their packets - a guess, by port or address, is kept out of the tables - those it
         * did not name, and the last error, with what reading the installed nDPI's catalogue found
         * wrong (it stays until the catalogue is read again).
         */
        function draw(data) {
            const $cards = $('#ac-cards').empty();
            if (!data || data.error && !data.totals) {
                $cards.append(card('bad', 'fa-shapes', "{{ lang._('Application Control') }}", "{{ lang._('Status could not be read.') }}", ''));
                return;
            }
            const totals = data.totals || {};
            const named = (data.apps || []).filter(function (a) { return a.named > 0; }).length;
            let state = '', sub = '';
            if (!data.classify) {
                sub = "{{ lang._('classifying is off') }}";
            } else if (!data.installed) {
                state = 'bad';
                sub = "{{ lang._('nDPI is not installed') }}";
            } else if (!data.running) {
                state = 'bad';
                sub = "{{ lang._('classifier not running') }}";
            } else {
                state = 'ok';
                sub = "{{ lang._('since') }}" + ' ' + when(data.since);
            }
            $cards.append(card(state, 'fa-shapes', "{{ lang._('Applications') }}", data.classify ? String(named) : "{{ lang._('off') }}", sub));
            $cards.append(card(totals.named ? 'ok' : '', 'fa-check', "{{ lang._('Classified') }}", count(totals.named),
                count(totals.guessed) + ' ' + "{{ lang._('guessed, kept out of tables') }}"));
            $cards.append(card('', 'fa-question', "{{ lang._('Unknown') }}", count(totals.unknown),
                count(totals.no_app) + ' ' + "{{ lang._('more named by protocol alone') }}"));
            const error = data.error || null;
            const catalogue = Array.isArray(data.catalogue_errors) ? data.catalogue_errors : [];
            const lines = (error ? [error.message] : []).concat(catalogue);
            $cards.append(card(lines.length ? 'warn' : '', 'fa-exclamation-triangle', "{{ lang._('Last error') }}",
                error ? when(error.at) : (catalogue.length ? when(data.catalogue_read_at) : "{{ lang._('none') }}"),
                lines.join(' · ')));

            $('#ac-project').toggle(!!data.project);
            $('#ac-pf-alone').toggle(!data.project);
            $('#ac-missing').toggle(!data.installed);

            /* what is blocked: the applications, the connections cut, those dropped in hardware first, and
               whether os-xgs-npu's Cut in hardware is on - shown once something is chosen to be blocked */
            const blocking = data.blocking || {};
            const blocked = Array.isArray(blocking.apps) ? blocking.apps : [];
            const pending = Array.isArray(blocking.pending) ? blocking.pending : [];
            const hardware = blocking.hardware || null;
            let said = '';
            if (blocked.length) {
                said = "{{ lang._('Blocked:') }}" + ' ' + blocked.join(', ') + ' · ' + count(blocking.cut) + ' ' +
                    "{{ lang._('connections cut') }}";
                if (hardware) {
                    said += ' · ' + count(blocking.dropped) + ' ' + "{{ lang._('dropped in hardware first') }}";
                }
                said += ' · ' + count(blocking.packets) + ' ' + "{{ lang._('packets stopped') }}" + '.';
            }
            if (pending.length) {
                said += (said ? ' ' : '') + "{{ lang._('Chosen to be blocked, not applied yet:') }}" + ' ' +
                    pending.join(', ') + '.';
            }
            $('#ac-blocking').text(plain(said));
            $('#ac-hw-on').toggle(!!(blocked.length && hardware && hardware.cut_in_hardware));
            $('#ac-hw-off').toggle(!!(blocked.length && hardware && !hardware.cut_in_hardware));
            $('#ac-blocking-line').toggle(said !== '');
            $('#ac-capped').text(plain(count(data.capped_windows) + ' ' +
                "{{ lang._('windows cut short: connections past the packets, connections or bytes a window reads were not classified') }}"))
                .toggle(data.capped_windows > 0);
            $('#ac-tables').text(count((data.tables || {}).categories) + ' ' + "{{ lang._('category tables') }}" + ' · ' +
                count((data.tables || {}).applications) + ' ' + "{{ lang._('application tables') }}" + ' · ' +
                count((data.tables || {}).addresses) + ' ' + "{{ lang._('addresses in pf') }}");
        }

        function refresh() {
            ajaxGet('/api/appcontrol/service/status', {}, draw);
        }

        /* The grids' rows are built by the API controller from the status script; the API escapes what
           it returns, so nothing here escapes it again. */
        $('#grid-apps').UIBootgrid({
            search: '/api/appcontrol/service/search_apps',
            options: {
                selection: false,
                formatters: {
                    category: function (column, row) {
                        return category(row.category);
                    },
                    number: function (column, row) {
                        return count(row[column.id]);
                    },
                    time: function (column, row) {
                        return when(row[column.id]);
                    },
                    table: function (column, row) {
                        if (!row.chosen && !row.blocked && !row.block_pending) {
                            return '<span class="text-muted">-</span>';
                        }
                        if (!row.table) {
                            return '<span class="text-warning">' + "{{ lang._('chosen, not applied yet') }}" + '</span>';
                        }
                        return '<code>' + row.table + '</code> ' + count(row.entries);
                    },
                    /* blocked: the connections cut, and the packets its block rule stopped */
                    blocked: function (column, row) {
                        if (row.blocked) {
                            return '<span class="text-danger"><i class="fa fa-ban"></i> ' + "{{ lang._('blocked') }}" +
                                '</span> · ' + count(row.cut) + ' ' + "{{ lang._('connections cut') }}" + ' · ' +
                                count(row.packets) + ' ' + "{{ lang._('packets stopped') }}";
                        }
                        if (row.block_pending) {
                            return '<span class="text-warning">' + "{{ lang._('chosen, not applied yet') }}" + '</span>';
                        }
                        return '<span class="text-muted">-</span>';
                    }
                }
            }
        });

        $('#grid-categories').UIBootgrid({
            search: '/api/appcontrol/service/search_categories',
            options: {
                selection: false,
                formatters: {
                    category: function (column, row) {
                        return category(row.name);
                    },
                    alias: function (column, row) {
                        return '<code>' + row.table + '</code>';
                    },
                    number: function (column, row) {
                        return count(row[column.id]);
                    }
                }
            }
        });

        $('#grid-unknown').UIBootgrid({
            search: '/api/appcontrol/service/search_unknown',
            options: {
                selection: false,
                formatters: {
                    kind: function (column, row) {
                        return (kinds[row.kind] || row.kind) + (row.name ? ': ' + row.name : '');
                    },
                    proto: function (column, row) {
                        return protocols[row.proto] || String(row.proto);
                    },
                    mono: function (column, row) {
                        return row[column.id] ? '<code>' + row[column.id] + '</code>' : '-';
                    },
                    ltr: function (column, row) {
                        return row[column.id] ? '<span dir="ltr">' + row[column.id] + '</span>' : '-';
                    },
                    number: function (column, row) {
                        return count(row[column.id]);
                    },
                    time: function (column, row) {
                        return when(row[column.id]);
                    }
                }
            }
        });

        /* the cards, and the grids of the tab on screen */
        $('#refreshAct').click(function () {
            refresh();
            const tab = $('#maintabs li.active a').attr('href');
            if (tab === '#applications') {
                $('#grid-apps').bootgrid('reload');
                $('#grid-categories').bootgrid('reload');
            } else if (tab === '#unknown') {
                $('#grid-unknown').bootgrid('reload');
            }
        });

        mapDataToFormUI({'frm_general': '/api/appcontrol/settings/get'}).done(function () {
            $('.selectpicker').selectpicker('refresh');
        });

        /* Apply: the settings saved, then the aliases, the filter, cron and the classifier (reconfigure) */
        $('#applyAct').click(function () {
            const $button = $(this).prop('disabled', true);
            const $progress = $('#frm_general_progress').addClass('fa fa-spinner fa-pulse');
            const done = function () {
                $progress.removeClass('fa fa-spinner fa-pulse');
                $button.prop('disabled', false);
            };
            saveFormToEndpoint('/api/appcontrol/settings/set', 'frm_general', function () {
                ajaxCall('/api/appcontrol/service/reconfigure', {}, function (data) {
                    done();
                    const lines = (data && data.changes ? data.changes : []).concat(data && data.errors ? data.errors : []);
                    const released = data && data.released ? data.released.released : null;
                    if (typeof released === 'number' && released > 0) {
                        lines.push(count(released) + ' ' + "{{ lang._('connections handed back from hardware') }}");
                    }
                    $('#ac-result').attr('class', data && data.status === 'ok' ? 'text-muted' : 'alert alert-danger')
                        .text(plain(lines.length ? lines.join(' · ') : "{{ lang._('Nothing to change in aliases.') }}")).show();
                    refresh();
                    $('#grid-apps').bootgrid('reload');
                    $('#grid-categories').bootgrid('reload');
                });
            }, false, done);
        });

        cards_wait('#ac-cards', ["{{ lang._('Applications') }}", "{{ lang._('Classified') }}", "{{ lang._('Unknown') }}",
            "{{ lang._('Last error') }}"]);
        refresh();
        keep_tab();
    });
</script>

<div class="xgs-cards xgs-top" id="ac-cards"></div>
<div class="text-muted clearfix" style="padding: 0 0 10px;">
    <button id="refreshAct" class="btn btn-default btn-xs pull-right" type="button" title="{{ lang._('Refresh') }}"><i class="fa fa-fw fa-refresh"></i></button>
    <span id="ac-project" style="display: none;">{{ lang._('os-xgs-npu is installed: each connection is classified from its first packets, seen by the host before it moves into hardware.') }}</span>
    <span id="ac-pf-alone" style="display: none;">{{ lang._('pf alone holds these tables: without os-xgs-npu no hardware takes part.') }}</span>
    <span id="ac-missing" class="text-warning" style="display: none;">{{ lang._('nDPI is not installed: package ndpi is needed.') }}</span>
    <span id="ac-capped" class="text-warning" style="display: none;"></span>
</div>
<div id="ac-blocking-line" class="text-muted" style="padding: 0 0 10px; display: none;">
    <span id="ac-blocking"></span>
    <span id="ac-hw-on" style="display: none;">{{ lang._('Cut in hardware is on in XGS: Settings: a connection cut is dropped on the coprocessor first.') }}</span>
    <span id="ac-hw-off" style="display: none;">{{ lang._('Cut in hardware is off in XGS: Settings: a connection cut leaves hardware once pf has let go of its state.') }}</span>
</div>

<ul class="nav nav-tabs" data-tabs="tabs" id="maintabs">
    <li class="active"><a data-toggle="tab" href="#applications">{{ lang._('Applications') }}</a></li>
    <li><a data-toggle="tab" href="#unknown">{{ lang._('Unknown') }}</a></li>
    <li><a data-toggle="tab" href="#settings">{{ lang._('Settings') }}</a></li>
</ul>

<div class="tab-content content-box">
    <div id="applications" class="tab-pane active">
        <table id="grid-apps" class="table table-condensed table-hover table-striped table-responsive">
            <thead>
                <tr>
                    <th data-column-id="name" data-type="string" data-identifier="true">{{ lang._('Application') }}</th>
                    <th data-column-id="category" data-formatter="category" data-type="string">{{ lang._('Category') }}</th>
                    <th data-column-id="protocols" data-type="string">{{ lang._('Carried by') }}</th>
                    <th data-column-id="named" data-formatter="number" data-type="numeric" data-width="9em">{{ lang._('Connections') }}</th>
                    <th data-column-id="guessed" data-formatter="number" data-type="numeric" data-width="8em">{{ lang._('Guessed') }}</th>
                    <th data-column-id="last" data-formatter="time" data-type="numeric">{{ lang._('Last seen') }}</th>
                    <th data-column-id="table" data-formatter="table" data-type="string">{{ lang._('Table') }}</th>
                    <th data-column-id="blocked" data-formatter="blocked" data-type="string" data-sortable="false">{{ lang._('Blocked') }}</th>
                </tr>
            </thead>
            <tbody></tbody>
            <tfoot></tfoot>
        </table>
        <div class="text-muted ac-note">
            {{ lang._('Connections: named by nDPI from their packets since the classifier started. Guessed: named by port or address only, never put in a table. Each connection counts once, in the window it began in.') }}
            {{ lang._('Blocked: chosen in Blocked applications. Connections cut: those nDPI named as it, their pf states killed. Packets stopped: dropped by its block rule, which a new connection to a server in its table meets.') }}
        </div>
        <table id="grid-categories" class="table table-condensed table-hover table-striped table-responsive">
            <thead>
                <tr>
                    <th data-column-id="name" data-formatter="category" data-type="string" data-identifier="true">{{ lang._('Category') }}</th>
                    <th data-column-id="table" data-formatter="alias" data-type="string">{{ lang._('Alias') }}</th>
                    <th data-column-id="entries" data-formatter="number" data-type="numeric" data-width="9em">{{ lang._('Addresses') }}</th>
                </tr>
            </thead>
            <tbody></tbody>
            <tfoot></tfoot>
        </table>
        <div class="text-muted ac-note">
            <span id="ac-tables"></span>.
            {{ lang._('Each table is an External alias in Firewall: Aliases, for a rule\'s source or destination: servers nDPI named, each kept until unseen for the address expiry. The table of an application chosen in Blocked applications has a block rule of this plugin\'s as well.') }}
        </div>
    </div>
    <div id="unknown" class="tab-pane">
        <table id="grid-unknown" class="table table-condensed table-hover table-striped table-responsive">
            <thead>
                <tr>
                    <th data-column-id="id" data-type="string" data-identifier="true" data-visible="false">{{ lang._('ID') }}</th>
                    <th data-column-id="kind" data-formatter="kind" data-type="string">{{ lang._('nDPI') }}</th>
                    <th data-column-id="proto" data-formatter="proto" data-type="numeric" data-width="6em">{{ lang._('Protocol') }}</th>
                    <th data-column-id="server" data-formatter="ltr" data-type="string">{{ lang._('Server') }}</th>
                    <th data-column-id="port" data-type="numeric" data-width="6em">{{ lang._('Port') }}</th>
                    <th data-column-id="server_name" data-formatter="ltr" data-type="string">{{ lang._('Server name') }}</th>
                    <th data-column-id="ja4" data-formatter="mono" data-type="string">{{ lang._('JA4') }}</th>
                    <th data-column-id="connections" data-formatter="number" data-type="numeric" data-width="8em">{{ lang._('Connections') }}</th>
                    <th data-column-id="last" data-formatter="time" data-type="numeric">{{ lang._('Last seen') }}</th>
                    <th data-column-id="interfaces" data-type="string" data-visible="false">{{ lang._('Interfaces') }}</th>
                </tr>
            </thead>
            <tbody></tbody>
            <tfoot></tfoot>
        </table>
        <div class="text-muted ac-note">
            {{ lang._('Not named: nDPI could not say what a connection is. Guessed: named by port or address only. No application: nDPI named its protocol - TLS, QUIC or HTTP - and no application on top. Not named and No application list only connections whose beginning was seen. Server name and JA4 fingerprint are what its client sent first, to tell where it comes from; JA4 is read from TLS over TCP only. Latest 500 of each kind kept.') }}
        </div>
    </div>
    <div id="settings" class="tab-pane">
        {{ partial("layout_partials/base_form", ['fields': generalForm, 'id': 'frm_general', 'apply_btn_id': 'applyAct']) }}
        <div style="padding: 0 15px 15px;"><div id="ac-result" style="display: none;"></div></div>
    </div>
</div>

{{ partial("OPNsense/AppControl/credit") }}
