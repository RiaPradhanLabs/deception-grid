#!/usr/bin/env python3
"""
ingest.py -- Cowrie's JSON log into SQLite, for the Deception Grid project.

Three design rules, in order of importance:

  1. Nothing is thrown away. Every line that parses becomes a row, with the
     original text kept in `raw`. Lines that do not parse go to `rejects`.
  2. Exclusions are labelled, not deleted. A row that should not count gets a
     reason in `excluded`. It stays in the database: queryable, countable,
     and arguable.
  3. Re-running is safe. A row's identity is the SHA-256 of its log line, so
     a second run recognises everything it already holds.

Run as:   sudo python3 ingest.py

sudo is needed to read the cowrie user's log. The database is handed back to
the invoking user at the end, so day-to-day queries need no privileges.

Two environment variables exist for testing against a sample log:
DECOY_LOGS overrides the log glob, DECOY_DB overrides the database path.
Neither is needed in normal use.
"""

import datetime
import glob
import hashlib
import json
import os
import re
import sqlite3

HERE     = os.path.dirname(os.path.abspath(__file__))
DB       = os.environ.get('DECOY_DB', os.path.join(HERE, 'decoy.sqlite'))
SCHEMA   = os.path.join(HERE, 'schema.sql')
EXCLUDES = os.path.join(HERE, 'exclude-ips.txt')
LOGS     = os.environ.get('DECOY_LOGS',
                          '/home/cowrie/cowrie/var/log/cowrie/cowrie.json*')

LOGIN_EVENTS = ('cowrie.login.success', 'cowrie.login.failed')

# Cowrie writes a non-printable byte in a credential as the LITERAL TEXT of a
# C escape -- the four characters \, x, 0, 0 -- not as the byte itself. Checked
# against the database on 29 September: hex(username) for the commonest pair is
# 656E61626C655C783030, which is "enable" followed by 5C 78 30 30. A first
# version of this rule tested for a real NUL byte and matched nothing at all.
ESCAPED_BYTE = re.compile(r'\\x[0-9a-fA-F]{2}')


def now():
    """UTC, to the second. Everything in this project is UTC."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')


def load_own_addresses(path):
    """Our own addresses. One per line; '#' comments and blank lines ignored.

    This file is never committed: it holds the analyst's home addresses.
    Top it up whenever the home connection rotates, with:

        echo "${SSH_CLIENT%% *}" >> exclude-ips.txt
        sort -u -o exclude-ips.txt exclude-ips.txt
    """
    ips = set()
    if os.path.exists(path):
        with open(path) as fh:
            for line in fh:
                line = line.split('#', 1)[0].strip()
                if line:
                    ips.add(line)
    return ips


def exclusion_reason(event, own):
    """Why this row must not count, or None if it counts.

    Exactly three reasons, and no others:

      loopback  our own local testing, from 127.0.0.1.
      analyst   a session from one of our own addresses.
      artefact  a 'login attempt' that is not one. Cowrie's telnet handler
                sometimes reads a stream of commands as login input and
                records it as a username/password pair. Those carry an
                escape for a non-printable byte, written as literal text;
                a credential somebody actually typed does not. The rule is
                the escape rather than a list of the pairs we happen to
                have seen, so it also catches variants we have not seen.

    Anything else counts. If a fourth reason is ever added, it goes here and
    it goes in the documentation, because the exclusion list is part of the
    result and not an implementation detail.
    """
    src = event.get('src_ip')
    if src == '127.0.0.1':
        return 'loopback'
    if src in own:
        return 'analyst'
    if event.get('eventid') in LOGIN_EVENTS:
        for field in ('username', 'password'):
            if ESCAPED_BYTE.search(event.get(field) or ''):
                return 'artefact'
    return None


def report(db):
    """Print what is in the database. Read this, do not retype the numbers."""

    def one(sql):
        return db.execute(sql).fetchone()

    print()
    print('=== every row in the database, by whether it counts ===')
    for reason, n in db.execute(
            "SELECT COALESCE(excluded, '(counts)'), COUNT(*) "
            "FROM events GROUP BY 1 ORDER BY 2 DESC"):
        print('  %-10s %7d' % (reason, n))

    print()
    print('=== the numbers that go in the write-up ===')
    print('  distinct sources        %d' % one(
        'SELECT COUNT(DISTINCT src_ip) FROM v_events '
        'WHERE src_ip IS NOT NULL')[0])
    print('  connections             %d' % one(
        "SELECT COUNT(*) FROM v_events "
        "WHERE eventid = 'cowrie.session.connect'")[0])
    print('  real password attempts  %d' % one(
        'SELECT COUNT(*) FROM v_logins')[0])
    n, s = one('SELECT COUNT(*), COUNT(DISTINCT src_ip) '
               'FROM v_logins WHERE ok = 1')
    print('  successful logins       %d, from %d sources' % (n, s))
    first, last = one('SELECT MIN(ts), MAX(ts) FROM v_events')
    print('  first event             %s' % first)
    print('  last event              %s' % last)

    print()
    print('  EVENTS by destination port')
    for port, n in db.execute(
            'SELECT dst_port, COUNT(*) FROM v_events '
            'WHERE dst_port IS NOT NULL GROUP BY 1 ORDER BY 2 DESC'):
        print('    %-6s %7d' % (port, n))

    print()
    print('  CONNECTIONS by destination port -- not the same thing')
    for port, n in db.execute(
            "SELECT dst_port, COUNT(*) FROM v_events "
            "WHERE eventid = 'cowrie.session.connect' "
            "GROUP BY 1 ORDER BY 2 DESC"):
        print('    %-6s %7d' % (port, n))

    print()
    print('=== excluded as an artefact, so the rule can be checked ===')
    rows = list(db.execute(
        "SELECT username, password, COUNT(*) FROM events "
        "WHERE excluded = 'artefact' GROUP BY 1, 2 ORDER BY 3 DESC"))
    if not rows:
        print('    none')
    for u, p, n in rows:
        print('    %-26r %-26r %5d' % (u, p, n))

    rejected = one('SELECT COUNT(*) FROM rejects')[0]
    if rejected:
        print()
        print('=== lines that would not parse: %d ===' % rejected)
        for line, why in db.execute(
                'SELECT line, why FROM rejects ORDER BY id LIMIT 5'):
            print('    %s' % why)
            print('      %s' % line[:120])


def main():
    own = load_own_addresses(EXCLUDES)
    files = sorted(glob.glob(LOGS))
    if not files:
        raise SystemExit('No log files matched %s' % LOGS)

    db = sqlite3.connect(DB)
    with open(SCHEMA) as fh:
        db.executescript(fh.read())

    started = now()
    cur = db.cursor()
    cur.execute('INSERT INTO runs (started) VALUES (?)', (started,))
    run_id = cur.lastrowid

    read = inserted = skipped = rejected = 0

    for path in files:
        with open(path, errors='replace') as fh:
            for line in fh:
                line = line.rstrip('\n')
                if not line.strip():
                    continue
                read += 1
                sha = hashlib.sha256(line.encode('utf-8', 'replace')).hexdigest()

                try:
                    e = json.loads(line)
                    if not isinstance(e, dict):
                        raise ValueError('not a JSON object')
                    if 'eventid' not in e or 'timestamp' not in e:
                        raise ValueError('missing eventid or timestamp')
                except Exception as exc:
                    cur.execute(
                        'INSERT OR IGNORE INTO rejects '
                        '(line_sha, seen, line, why) VALUES (?,?,?,?)',
                        (sha, started, line,
                         '%s: %s' % (type(exc).__name__, exc)))
                    rejected += 1
                    continue

                cur.execute("""
                    INSERT OR IGNORE INTO events
                      (line_sha, ts, eventid, sensor, session, src_ip,
                       src_port, dst_port, username, password, input,
                       message, raw, excluded)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    sha,
                    e['timestamp'],
                    e['eventid'],
                    e.get('sensor'),
                    e.get('session'),
                    e.get('src_ip'),
                    e.get('src_port'),
                    e.get('dst_port'),
                    e.get('username'),
                    e.get('password'),
                    e.get('input'),
                    e.get('message'),
                    line,
                    exclusion_reason(e, own),
                ))
                if cur.rowcount:
                    inserted += 1
                else:
                    skipped += 1

    cur.execute('UPDATE runs SET finished = ?, lines_read = ?, inserted = ?, '
                'skipped = ?, rejected = ? WHERE id = ?',
                (now(), read, inserted, skipped, rejected, run_id))
    db.commit()

    print()
    print('=== this run ===')
    print('  log files         %s'
          % ', '.join(os.path.basename(f) for f in files))
    print('  own addresses     %d loaded from %s'
          % (len(own), os.path.basename(EXCLUDES)))
    print('  lines read        %d' % read)
    print('  rows inserted     %d' % inserted)
    print('  already held      %d' % skipped)
    print('  would not parse   %d' % rejected)

    report(db)
    db.close()

    # Hand the database back, so queries afterwards need no sudo.
    uid, gid = os.environ.get('SUDO_UID'), os.environ.get('SUDO_GID')
    if uid and gid:
        for suffix in ('', '-wal', '-shm'):
            p = DB + suffix
            if os.path.exists(p):
                os.chown(p, int(uid), int(gid))


if __name__ == '__main__':
    main()
