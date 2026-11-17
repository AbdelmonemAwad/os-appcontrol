#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""The installer, the removal, the package's three scripts, place-menu.sh and the rc script, run in a
temporary root.

As os-trafficpriority's test: the scripts are run with sh from a copy of the repository in which their
absolute paths are moved into the temporary root - /usr/local, /var/db/os-appcontrol, /var/run, PHP's
/var/lib/php/tmp, the caches in /tmp, /conf/config.xml, /sbin/pfctl, /bin/pkill, /sbin/mount,
/sbin/umount, /usr/sbin/daemon, /etc/rc.subr - and stand-ins answer for what only a firewall has:
service, configctl, pkg, pfctl, pkill, mount, umount, daemon and rc.subr, each writing down how it was
called (pkill kills nothing here; mount and umount keep a table of their own). Two things FreeBSD does
otherwise are bridged in the copy: BSD's `cp -R dir/` copies what dir holds, written `dir/.` for GNU's
cp; BSD's `mktemp -t prefix` takes a prefix, which a stand-in gives GNU's mktemp; and install's -o root
-g wheel, which a test run by anyone cannot take, is left out by a stand-in.

What is checked is what the scripts do: which files are laid down with which modes, where the menu
goes, that nothing is copied when a file has a syntax error, the package ndpi installed when it is
not there and removed only when the installer installed it and nothing needs it, the aliases made
and the classifier started (on by default) or stopped (off in Settings), the window files' tmpfs
mounted at the classifier's start and taken down at its stop, the classifier stopped and the aliases
taken out before the files go, the tmpfs taken down by every removal, the tables of aliases gone
emptied, nothing of the plugin left, and nothing done by the old package's pre-deinstall in an upgrade.

    python3 tools/test-install.py"""
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = ['install/install.sh', 'install/uninstall.sh', 'install/enable.sh', 'pkg/post-install.sh',
           'pkg/pre-deinstall.sh', 'pkg/post-deinstall.sh', 'src/opnsense/scripts/appcontrol/place-menu.sh',
           'src/opnsense/scripts/appcontrol/tables.py', 'src/etc/rc.d/appcontrol']
LOCAL = '/usr/local'
MENU = '/usr/local/opnsense/mvc/app/models/OPNsense/AppControl/Menu/Menu.xml'
XGS = '/usr/local/opnsense/mvc/app/models/OPNsense/XGS/Menu/Menu.xml'
HOOK = '/usr/local/etc/inc/plugins.inc.d/appcontrol.inc'
RC = '/usr/local/etc/rc.d/appcontrol'
STATE = '/var/db/os-appcontrol'
WORK = STATE + '/work'
# rc.subr as far as rc.d/appcontrol asks it
RC_SUBR = ('load_rc_config() { :; }\nwarn() { echo "${name}: WARNING: $*" >&2; }\n'
           'run_rc_command() {\n\tcase "$1" in\n\t*start) ${start_cmd} ;;\n\t*stop) ${stop_cmd} ;;\n'
           '\t*status) ${status_cmd} ;;\n\tesac\n}\n')
CACHES = ['/var/lib/php/tmp/opnsense_menu_cache.xml', '/var/lib/php/tmp/opnsense_acl_cache.json',
          '/tmp/opnsense_menu_cache.xml', '/tmp/opnsense_acl_cache.json']
COMMIT = '0123456789abcdef0123456789abcdef01234567'
ON = '<opnsense><OPNsense><AppControl><general><classify>1</classify></general></AppControl></OPNsense></opnsense>'
OFF = '<opnsense><OPNsense><AppControl><general><classify>0</classify></general></AppControl></OPNsense></opnsense>'

failures = 0
checks = 0


def check(name, got, want):
    global failures, checks
    checks += 1
    ok = got == want
    failures += 0 if ok else 1
    print('%s %s%s' % ('ok  ' if ok else 'FAIL', name, '' if ok else ' - got %r, want %r' % (got, want)))


class Box:
    """A temporary root, a copy of the repository whose scripts work in it, and the stand-ins."""

    def __init__(self, tmp):
        self.fake = os.path.join(tmp, 'root')
        self.repo = os.path.join(tmp, 'repo')
        self.bin = os.path.join(tmp, 'bin')
        self.calls = os.path.join(tmp, 'calls')
        self.pkgdb = os.path.join(tmp, 'pkgdb')
        self.tables = os.path.join(tmp, 'pf-tables')
        os.makedirs(self.fake)
        os.makedirs(self.bin)
        os.makedirs(self.pkgdb)
        shutil.copytree(ROOT, self.repo, ignore=shutil.ignore_patterns('.git', '__pycache__', '*.pyc'))
        # every file as a checkout has it, not runnable: the scripts set what must be
        for base, _, files in os.walk(self.repo):
            for name in files:
                os.chmod(os.path.join(base, name), 0o644)
        for script in SCRIPTS:
            path = os.path.join(self.repo, script)
            text = open(path, encoding='utf-8').read()
            # a path where one starts, not one inside another (/var/lib/php/tmp/ holds /tmp/ too)
            text = re.sub(r'(?<![\w/.-])(/usr/local/|/var/lib/php/tmp/|/tmp/opnsense_|/sbin/pfctl|/var/db/os-appcontrol|'
                          r'/var/run/appcontrol|/conf/config\.xml|/bin/pkill|/sbin/u?mount\b|/usr/sbin/daemon\b|'
                          r'/etc/rc\.subr)',
                          lambda m: self.fake + m.group(1), text)
            text = text.replace('cp -R "${HERE}/src/" ', 'cp -R "${HERE}/src/." ')
            with open(path, 'w', encoding='utf-8', newline='\n') as handle:
                handle.write(text)
        hook = self.fake + HOOK
        log = self.calls
        self.stub('configctl', 'echo "configctl $* hook=$([ -f %s ] && echo yes || echo no)" >> %s\necho OK' % (hook, log))
        self.stub('service', 'echo "service $*" >> %s' % log)
        self.stub('mktemp', 'if [ "$1" = -d ] && [ "$2" = -t ]; then exec /usr/bin/env mktemp -d '
                            '"${TMPDIR:-/tmp}/$3.XXXXXX"; fi\nexec /usr/bin/env mktemp "$@"', real='mktemp')
        self.stub('install', 'a=""\nwhile [ $# -gt 0 ]; do case "$1" in -o|-g) shift 2 ;; *) a="$a \'$1\'"; shift ;; '
                             'esac; done\neval exec /usr/bin/env install $a', real='install')
        # pkg: ndpi installed when its file is in pkgdb; what needs it, from pkgdb/needs
        self.stub('pkg', 'echo "pkg $*" >> %s\ncase "$1 $2" in\n'
                         '"info -e") [ -f %s/$3 ] ;;\n'
                         '"install -y") [ -f %s/broken ] && exit 1; touch %s/$3 ;;\n'
                         '"query %%rn") cat %s/needs 2>/dev/null ;;\n'
                         '"delete -y") rm -f %s/$3 ;;\nesac'
                  % (log, self.pkgdb, self.pkgdb, self.pkgdb, self.pkgdb, self.pkgdb))
        os.makedirs(self.fake + '/sbin')
        self.write(self.fake + '/sbin/pfctl', '#!/bin/sh\necho "pfctl $*" >> %s\n'
                   'case "$*" in "-v -s Tables") cat %s 2>/dev/null ;; esac\n' % (log, self.tables), 0o755)
        os.makedirs(self.fake + '/bin')
        self.write(self.fake + '/bin/pkill', '#!/bin/sh\necho "pkill $*" >> %s\nexit 1\n' % log, 0o755)
        # mount -p lists the table kept here; mount -t ... adds its last argument, umount takes it out
        self.mounts = os.path.join(tmp, 'mounts')
        self.write(self.mounts, '')
        self.write(self.fake + '/sbin/mount', '#!/bin/sh\n[ "$1" = -p ] && exec cat %s\necho "mount $*" >> %s\n'
                   'for a; do d=$a; done\necho "tmpfs $d tmpfs rw 0 0" >> %s\n' % (self.mounts, log, self.mounts), 0o755)
        self.write(self.fake + '/sbin/umount', '#!/bin/sh\necho "umount $*" >> %s\nfor a; do d=$a; done\n'
                   'grep -q " $d " %s || exit 1\ngrep -v " $d " %s > %s.new; mv %s.new %s\n'
                   % (log, self.mounts, self.mounts, self.mounts, self.mounts, self.mounts), 0o755)
        self.write(self.fake + '/usr/sbin/daemon', '#!/bin/sh\necho "daemon $*" >> %s\n' % log, 0o755)
        self.write(self.fake + '/etc/rc.subr', RC_SUBR)
        os.makedirs(self.fake + '/conf')
        self.config(ON)

    def config(self, text):
        self.write(self.fake + '/conf/config.xml', text)

    def stub(self, name, body, real=None):
        path = os.path.join(self.bin, name)
        if real:
            # the stand-in must not find itself: the real one is looked for past this directory
            body = body.replace('/usr/bin/env %s' % real, shutil.which(real, path=os.defpath) or '/usr/bin/' + real)
        self.write(path, '#!/bin/sh\n' + body + '\n', 0o755)

    @staticmethod
    def write(path, text, mode=0o644):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8', newline='\n') as handle:
            handle.write(text)
        os.chmod(path, mode)

    def run(self, script, *args, env=None):
        return self.sh(os.path.join(self.repo, script), *args, env=env)

    def sh(self, path, *args, env=None):
        environ = dict(os.environ, PATH=self.bin + os.pathsep + os.environ.get('PATH', ''),
                       TMPDIR=os.path.dirname(self.fake))
        environ.update(env or {})
        done = subprocess.run(['sh', path] + list(args), env=environ, capture_output=True, text=True, timeout=300)
        return done.returncode, done.stdout + done.stderr

    def called(self, prefix=''):
        try:
            return [c for c in open(self.calls, encoding='utf-8').read().splitlines() if c.startswith(prefix)]
        except OSError:
            return []

    def forget(self):
        if os.path.exists(self.calls):
            os.remove(self.calls)

    def plugin_files(self):
        """Every file under the root that the plugin has a hand in."""
        out = []
        for base, _, files in os.walk(self.fake):
            for name in files:
                path = os.path.join(base, name)[len(self.fake):]
                if 'appcontrol' in path.lower():
                    out.append(path)
        return sorted(out)

    def mode(self, path):
        return stat.S_IMODE(os.stat(self.fake + path).st_mode)

    def read(self, path):
        try:
            return open(self.fake + path, encoding='utf-8').read()
        except OSError:
            return None

    def python3(self):
        """/usr/local/bin/python3 of the root: the test's own python3."""
        self.write(self.fake + '/usr/local/bin/python3', '#!/bin/sh\nexec %s "$@"\n' % sys.executable, 0o755)


def source_files():
    out = []
    for base, _, files in os.walk(os.path.join(ROOT, 'src')):
        for name in files:
            if name.endswith('.pyc') or '__pycache__' in base:
                continue
            out.append(LOCAL + os.path.join(base, name)[len(os.path.join(ROOT, 'src')):].replace(os.sep, '/'))
    return sorted(out)


with tempfile.TemporaryDirectory() as tmp:
    box = Box(tmp)
    menu_own = open(os.path.join(ROOT, 'src/opnsense/scripts/appcontrol/menu/own.xml'), encoding='utf-8').read()
    menu_xgs = open(os.path.join(ROOT, 'src/opnsense/scripts/appcontrol/menu/xgs.xml'), encoding='utf-8').read()
    place = 'src/opnsense/scripts/appcontrol/place-menu.sh'

    # place-menu.sh: XGS where os-xgs-npu's menu is, Firewall where it is not
    for cache in CACHES:
        box.write(box.fake + cache, 'cached')
    rc, out = box.run(place)
    check('place-menu.sh without os-xgs-npu: own, the Firewall menu file', (rc, out.strip(), box.read(MENU)),
          (0, 'own', menu_own))
    check('place-menu.sh: the menu caches cleared', [c for c in CACHES[::2] if os.path.exists(box.fake + c)], [])
    box.write(box.fake + XGS, '<menu/>')
    rc, out = box.run(place)
    check('place-menu.sh with os-xgs-npu: xgs, the XGS menu file, order 59', (rc, out.strip(), box.read(MENU),
          'order="59"' in menu_xgs), (0, 'xgs', menu_xgs, True))
    os.remove(box.fake + XGS)
    shutil.rmtree(box.fake + LOCAL)

    # install.sh: nothing copied when a file of the tree has a syntax error
    broken = os.path.join(box.repo, 'src/opnsense/mvc/app/library/OPNsense/AppControl/Aliases.php')
    kept = open(broken, encoding='utf-8').read()
    with open(broken, 'w', encoding='utf-8') as handle:
        handle.write(kept.replace('class Aliases', 'class Aliases {', 1))
    rc, out = box.run('install/install.sh')
    check('install.sh, a PHP file with a syntax error: stopped, nothing copied, nothing asked',
          (rc != 0, box.plugin_files(), box.called()), (True, [], []))
    with open(broken, 'w', encoding='utf-8') as handle:
        handle.write(kept)
    broken = os.path.join(box.repo, 'src/opnsense/scripts/appcontrol/classify.py')
    kept = open(broken, encoding='utf-8').read()
    with open(broken, 'w', encoding='utf-8') as handle:
        handle.write(kept + '\ndef broken(:\n')
    rc, out = box.run('install/install.sh')
    check('install.sh, a Python file with a syntax error: stopped, nothing copied', (rc != 0, box.plugin_files()), (True, []))
    with open(broken, 'w', encoding='utf-8') as handle:
        handle.write(kept)

    # install.sh: ndpi installed, every file of src/ laid down, the aliases, filter, cron, the classifier started
    for cache in CACHES:
        box.write(box.fake + cache, 'cached')
    box.write(os.path.join(box.repo, '.source-commit'), COMMIT + ' 2026-11-17T12:00:00+00:00\n')
    box.forget()
    rc, out = box.run('install/install.sh')
    check('install.sh: done, where the page is, and that it classifies', (rc, out.strip().splitlines()[-1:]),
          (0, ['Application Control installed: Firewall > Application Control (classifying)']))
    check('install.sh: the package ndpi installed, it not being there', box.called('pkg'), ['pkg info -e ndpi',
                                                                                          'pkg install -y ndpi'])
    laid = [f for f in box.plugin_files() if f.startswith(LOCAL) and not f.startswith('/usr/local/share/') and f != MENU]
    check('install.sh: every file of src/ laid down, and nothing else', laid, source_files())
    check('install.sh: the menu file placed, the caches cleared', (box.read(MENU), [c for c in CACHES if os.path.exists(box.fake + c)]),
          (menu_own, []))
    check('install.sh: configd restarted, then the aliases, the filter, cron, and the classifier started',
          box.called('configctl') + box.called('service'),
          ['configctl appcontrol apply hook=yes', 'configctl filter reload skip_alias hook=yes',
           'configctl cron restart hook=yes', 'configctl appcontrol restart hook=yes', 'service configd restart'])
    check('install.sh: the modes', [box.mode(p) for p in (
        '/usr/local/opnsense/scripts/appcontrol/classify.py', '/usr/local/opnsense/scripts/appcontrol/aliases.php',
        '/usr/local/opnsense/scripts/appcontrol/place-menu.sh', RC, HOOK,
        '/usr/local/opnsense/service/conf/actions.d/actions_appcontrol.conf',
        '/usr/local/opnsense/scripts/appcontrol/categories.json', '/usr/local/opnsense/scripts/appcontrol/i18n/ui/source.json',
        '/usr/local/opnsense/scripts/appcontrol/release-keys/xgs-release-key-13ed7f86.pub')],
        [0o755, 0o755, 0o755, 0o755, 0o644, 0o644, 0o644, 0o644, 0o644])
    check('install.sh: the state directory, 0750', box.mode(STATE), 0o750)
    installed = box.read('/usr/local/share/os-appcontrol/installed.json') or ''
    check('install.sh: the commit recorded for the self-update, and that it installed ndpi',
          ('"commit": "%s"' % COMMIT in installed, os.path.exists(box.fake + '/usr/local/share/os-appcontrol/ndpi-installed')),
          (True, True))

    # install.sh again: ndpi there, classifying off in Settings, os-xgs-npu there
    box.config(OFF)
    box.write(box.fake + XGS, '<menu/>')
    os.remove(box.fake + '/usr/local/share/os-appcontrol/ndpi-installed')
    box.forget()
    rc, out = box.run('install/install.sh')
    check('install.sh again, classifying off: XGS > Application Control, the classifier stopped, ndpi left as it is',
          (rc, out.strip().splitlines()[-1:], box.called('configctl appcontrol'), box.called('pkg')),
          (0, ['Application Control installed: XGS > Application Control (classifying is off in Settings)'],
           ['configctl appcontrol apply hook=yes', 'configctl appcontrol stop hook=yes'], ['pkg info -e ndpi']))
    check('install.sh again: ndpi there before, so not marked as installed by it',
          os.path.exists(box.fake + '/usr/local/share/os-appcontrol/ndpi-installed'), False)

    # the rc script, as installed: the window files' tmpfs mounted at the start, once, taken down at the stop
    work, run_dir = box.fake + WORK, box.fake + '/var/run'
    box.forget()
    rc, out = box.sh(box.fake + RC, 'onestart')
    check('rc.d/appcontrol onestart: a tmpfs of 160m mounted on the work directory, then the classifier started',
          (rc, box.called(), os.path.isdir(work)),
          (0, ['mount -t tmpfs -o size=160m,mode=0750 tmpfs %s' % work,
               'daemon -f -R 10 -t appcontrol -P %s/appcontrol.daemon.pid -p %s/appcontrol.pid '
               '%s/usr/local/opnsense/scripts/appcontrol/classify.py run' % (run_dir, run_dir, box.fake)], True))
    box.forget()
    box.sh(box.fake + RC, 'onestart')
    check('rc.d/appcontrol onestart, the tmpfs there already: not mounted over it', box.called('mount'), [])
    box.forget()
    rc, out = box.sh(box.fake + RC, 'onestop')
    check('rc.d/appcontrol onestop, nothing running: the tmpfs taken down', (rc, box.called(), open(box.mounts).read(),
                                                                             out.strip()),
          (0, ['umount %s' % work], '', 'appcontrol is not running.'))
    box.sh(box.fake + RC, 'onestart')
    # daemon(8) supervising the classifier, as ps shows it
    daemon = subprocess.Popen(['daemon: appcontrol[1]', '60'], executable=shutil.which('sleep'))
    threading.Thread(target=daemon.wait, daemon=True).start()
    box.write(run_dir + '/appcontrol.daemon.pid', str(daemon.pid))
    box.forget()
    rc, out = box.sh(box.fake + RC, 'onestop')
    check('rc.d/appcontrol onestop, the classifier running: stopped, then the tmpfs taken down',
          (rc, daemon.poll() is not None, box.called(), open(box.mounts).read(), os.path.exists(run_dir + '/appcontrol.daemon.pid')),
          (0, True, ['umount %s' % work], '', False))

    # uninstall.sh: the classifier and the aliases first, then the files; ndpi left, not installed by it
    os.remove(box.fake + XGS)
    box.write(box.fake + RC, '#!/bin/sh\necho "rc.d appcontrol $* hook=$([ -f %s ] && echo yes || echo no)" >> %s\n'
              % (box.fake + HOOK, box.calls), 0o755)
    box.write(box.fake + STATE + '/status.json', '{}')
    os.makedirs(box.fake + '/usr/local/opnsense/scripts/appcontrol/__pycache__', exist_ok=True)
    box.write(box.tables, '-pa----\tappcontrol_cat_Gone\n-pa-r--\tappcontrol_cat_Used\n-pa----\tappcontrol_cat_Web\n'
                          '-pa----\tbogons\n')
    box.config(ON.replace('</OPNsense>', '<Firewall><Alias><aliases><alias><name>appcontrol_cat_Web</name></alias>'
                                         '</aliases></Alias></Firewall></OPNsense>'))
    box.forget()
    rc, out = box.run('install/uninstall.sh')
    calls = box.called()
    check('uninstall.sh: the classifier stopped and its aliases taken out while the hook is there, first',
          calls[:4], ['rc.d appcontrol onestop hook=yes', 'pkill -f daemon: [a]ppcontrol\\[',
                      'pkill -f %s/usr/local/opnsense/scripts/[a]ppcontrol/' % box.fake, 'configctl appcontrol remove hook=yes'])
    check('uninstall.sh: nothing of the plugin left - files, state, pidfiles', box.plugin_files(), [])
    check('uninstall.sh: the window files\' tmpfs taken down, should the rc script not have', box.called('umount'),
          ['umount -f %s' % (box.fake + WORK)])
    check('uninstall.sh: then configd, the filter and cron, without the hook',
          [c for c in calls if c.startswith(('service', 'configctl filter', 'configctl cron'))],
          ['service configd restart', 'configctl filter reload skip_alias hook=no', 'configctl cron restart hook=no'])
    check('uninstall.sh: the table of an alias gone taken out of pf; one a rule uses, one whose alias is there, and pf\'s own left',
          box.called('pfctl -t'), ['pfctl -t appcontrol_cat_Gone -T kill'])
    check('uninstall.sh: ndpi left, as it was there before', (box.called('pkg'), rc, out.strip().splitlines()[-1]),
          ([], 0, 'Application Control removed; its settings stay in config.xml'))

    # install.sh, ndpi not there; uninstall.sh removes it only when nothing needs it
    os.remove(os.path.join(box.pkgdb, 'ndpi'))
    box.config(ON)
    box.run('install/install.sh')
    box.write(os.path.join(box.pkgdb, 'needs'), 'ntopng\n')
    box.forget()
    rc, out = box.run('install/uninstall.sh')
    check('uninstall.sh, ndpi installed by install.sh but needed by another package: left, said',
          (box.called('pkg'), 'another package needs it' in out), (['pkg query %rn ndpi'], True))
    box.run('install/install.sh')
    os.remove(os.path.join(box.pkgdb, 'ndpi'))
    os.remove(os.path.join(box.pkgdb, 'needs'))
    box.run('install/install.sh')
    box.forget()
    rc, out = box.run('install/uninstall.sh')
    check('uninstall.sh, ndpi installed by install.sh and needed by nothing: removed', box.called('pkg'),
          ['pkg query %rn ndpi', 'pkg delete -y ndpi'])
    box.write(os.path.join(box.pkgdb, 'broken'), '')
    box.forget()
    rc, out = box.run('install/install.sh')
    check('install.sh, ndpi not to be had: installed all the same, said', (rc, 'could not be installed' in out),
          (0, True))
    os.remove(os.path.join(box.pkgdb, 'broken'))
    box.run('install/uninstall.sh')

    # the package: pkg lays down the files of src/, post-install does the Apply on by default; the old
    # package's pre-deinstall does nothing in an upgrade; a removal: classifier, aliases, then post-deinstall
    shutil.rmtree(box.fake + LOCAL)
    shutil.copytree(os.path.join(box.repo, 'src'), box.fake + LOCAL)
    for path in source_files():
        os.chmod(box.fake + path, 0o755 if open(box.fake + path, 'rb').read(2) == b'#!' else 0o644)
    box.write(box.fake + '/usr/local/sbin/configctl', '#!/bin/sh\nexec configctl "$@"\n', 0o755)
    box.write(box.fake + '/usr/local/etc/rc.d/configd', '#!/bin/sh\nservice configd "$@"\n', 0o755)
    box.python3()
    box.config(ON)
    box.forget()
    rc, out = box.run('pkg/post-install.sh')
    check('post-install.sh: the menu placed, the classifier started, said', (rc, box.read(MENU) == menu_own,
          out.strip().splitlines()[-1]), (0, True, 'Application Control installed: the page is at Firewall > Application Control '
                                                   '(classifying)'))
    check('post-install.sh: configd, then the aliases, the filter, cron and the classifier', box.called('configctl') +
          box.called('service'), ['configctl appcontrol apply hook=yes', 'configctl filter reload skip_alias hook=yes',
                                  'configctl cron restart hook=yes', 'configctl appcontrol restart hook=yes',
                                  'service configd restart'])
    check('post-install.sh: the state directory', box.mode(STATE), 0o750)
    box.config(OFF)
    box.forget()
    rc, out = box.run('pkg/post-install.sh')
    check('post-install.sh, classifying off: the classifier stopped', box.called('configctl appcontrol'),
          ['configctl appcontrol apply hook=yes', 'configctl appcontrol stop hook=yes'])
    box.write(box.fake + RC, '#!/bin/sh\necho "rc.d appcontrol $*" >> %s\n' % box.calls, 0o755)
    box.forget()
    rc, out = box.run('pkg/pre-deinstall.sh', env={'PKG_UPGRADE': 'true'})
    check('pre-deinstall.sh in an upgrade: nothing done', (rc, box.called()), (0, []))
    rc, out = box.run('pkg/pre-deinstall.sh', env={'PKG_UPGRADE': ''})
    check('pre-deinstall.sh in a removal: the classifier stopped, its tmpfs taken down, then the aliases taken out', box.called(),
          ['rc.d appcontrol onestop', 'pkill -f daemon: [a]ppcontrol\\[', 'pkill -f %s/usr/local/opnsense/scripts/[a]ppcontrol/' % box.fake,
           'umount -f %s' % (box.fake + WORK), 'configctl appcontrol remove hook=yes'])
    os.makedirs(box.fake + '/usr/local/opnsense/scripts/appcontrol/__pycache__', exist_ok=True)
    box.write(box.fake + '/usr/local/opnsense/scripts/appcontrol/__pycache__/classify.cpython-311.pyc', 'x')
    for path in source_files():
        os.remove(box.fake + path)
    box.write(box.fake + '/var/run/appcontrol.pid', '12345')
    box.forget()
    rc, out = box.run('pkg/post-deinstall.sh')
    check('post-deinstall.sh: nothing of the plugin left - the menu file, Python\'s caches, the state, the pidfile',
          box.plugin_files(), [])
    check('post-deinstall.sh: configd, the filter and cron, the table of an alias gone taken out of pf',
          box.called('service') + [c for c in box.called('configctl')] + box.called('pfctl -t'),
          ['service configd restart', 'configctl filter reload skip_alias hook=no', 'configctl cron restart hook=no',
           'pfctl -t appcontrol_cat_Gone -T kill', 'pfctl -t appcontrol_cat_Web -T kill'])
    check('post-deinstall.sh: the window files\' tmpfs taken down before the state goes', box.called('umount'),
          ['umount -f %s' % (box.fake + WORK)])

print('%d of %d checks failed' % (failures, checks) if failures else '%d checks passed' % checks)
sys.exit(1 if failures else 0)
