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
OT_LOGS  = os.environ.get('DECOY_OT_LOGS',
                          '/home/conpot/log/conpot.json*')

LOGIN_EVENTS = ('cowrie.login.success', 'cowrie.login.failed')

# Cowrie writes a non-printable byte in a credential as the LITERAL TEXT of a
# C escape -- the four characters \, x, 0, 0 -- not as the byte itself. Checked
# against the database on 29 September: hex(username) for the commonest pair is
# 656E61626C655C783030, which is "enable" followed by 5C 78 30 30. A first
# version of this rule tested for a real NUL byte and matched nothing at all.
ESCAPED_BYTE = re.compile(r'\\x[0-9a-fA-F]{2}')

# Console-escalation words. The distinction between a command and a password
# is semantic, not syntactic: 'enable' and 'blender' are the same shape, and a
# rule based on the escape alone excluded root/7ujMko0admin -- a real camera
# default that happens to arrive with a trailing null.
CONSOLE_WORDS = {'enable', 'system', 'shell', 'sh', 'linuxshell',
                 'su', 'exit', 'quit', 'help'}


def printable_part(value):
    return ESCAPED_BYTE.sub('', value or '').replace('\ufeff', '').strip()


def normalise_conpot(event):
    """Conpot's record in Cowrie's shape, so both decoys share one facts table.

    Conpot does not name a single field the way Cowrie does. Verified against
    the real log on 29 September 2026 rather than assumed -- these are the 17
    keys actually present:

        Cowrie          Conpot          note
        timestamp       event_time      session_time is the session's start and
                                        is kept in `raw`, not here.
        eventid         event_type      upper-case words: NEW_CONNECTION,
                                        CONNECTION_LOST, and the protocol
                                        events. Prefixed 'conpot.' and
                                        lower-cased, so an eventid always says
                                        which decoy it came from.
        sensor          sensorid        'decoy-01-ot'. The whole reason this
                                        field was set: Azure translates, so
                                        dst_ip is always the private address
                                        and cannot distinguish the two decoys.
        session         session_id      a uuid rather than Cowrie's short hex.
        src_ip/_port    same
        dst_port        same            502 once the OT door opens, 5020 before.
        input           request         the raw Modbus request. `response` is
                                        Conpot's reply and stays in `raw`: what
                                        the decoy said is not a finding about
                                        the visitor.
        username/pass   -               Modbus has no authentication at all,
                                        which is the point of the comparison.

    One facts table, not two. The alternative -- a second table for OT -- would
    make every cross-door question a join and give two places for the exclusion
    rules to disagree.
    """
    data = event.get('data') or {}
    return {
        'timestamp': event.get('event_time'),
        'eventid':   'conpot.' + str(event.get('event_type', 'unknown')).lower(),
        'sensor':    event.get('sensorid'),
        'session':   event.get('session_id'),
        'src_ip':    event.get('src_ip'),
        'src_port':  event.get('src_port'),
        'dst_port':  event.get('dst_port'),
        'username':  None,
        'password':  None,
        'input':     event.get('request'),
        'message':   json.dumps(data, sort_keys=True) if data else None,
    }


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

    Four reasons, and no others:

      loopback          our own local testing, from 127.0.0.1.
      analyst           a session from one of our own addresses.
      artefact-command  a 'login attempt' that is not one. Cowrie's telnet
                        handler sometimes reads a stream of commands as login
                        input and records it as a username/password pair.
      artefact-binary   a login row whose fields are non-printable bytes with
                        no readable content at all.

    Anything else counts. If a fifth reason is ever added, it goes here and it
    goes in the documentation, because the exclusion list is part of the result
    and not an implementation detail.

    The artefact rule took three attempts and the failures are the argument for
    how it is written now.

    Version one tested for a real NUL byte in either field and matched NOTHING,
    because Cowrie writes a non-printable byte as the literal text of a C escape
    -- the four characters \\, x, 0, 0. Verified against the database rather than
    assumed: hex(username) for the commonest pair is 656E61626C655C783030, which
    is "enable" followed by 5C 78 30 30. Caught because this function's output is
    printed on every run and the excluded list came back empty.

    Version two matched any \\xNN escape, and over-corrected. It threw out
    root/7ujMko0admin, root/founder88, root/blender and telnetadmin/telnetadmin
    -- real credential attempts that happen to arrive with a trailing null.
    7ujMko0admin is a well-known camera default. Caught by reading the excluded
    rows instead of trusting the total.

    Version three, below, accepts that the distinction is SEMANTIC and not
    syntactic: 'enable' and 'blender' are the same shape to any pattern, so only
    a list of console words separates a command from a password. An escape alone
    is not enough; what is left after the escapes are stripped has to be a
    console word, or empty, or unreadable. Tested against all 18 distinct cases
    observed in the first four days.
    """
    src = event.get('src_ip')
    if src == '127.0.0.1':
        return 'loopback'
    if src in own:
        return 'analyst'
    if event.get('eventid') in LOGIN_EVENTS:
        user, pw = event.get('username'), event.get('password')
        su, sp = printable_part(user), printable_part(pw)
        # Everything below is INSIDE this branch on purpose. Only a field that
        # carries an escape is a candidate; a credential containing an ordinary
        # non-ASCII character -- an accented letter, Cyrillic, CJK -- is a real
        # attempt and must not be touched. An earlier version had the
        # printability test outside this branch, which would have excluded any
        # such password as 'binary'. Nothing had hit it yet; it was latent.
        if ESCAPED_BYTE.search(user or '') or ESCAPED_BYTE.search(pw or ''):
            # Order matters. Test for garbage first, so that a field which
            # strips to nothing is labelled binary rather than command.
            #
            # Version four, 29 September 2026. Version three required BOTH
            # fields to survive stripping, and that was too broad: it excluded
            #
            #     username 'daemon\x00'   password ''
            #
            # as binary. An empty-password probe is ordinary, `daemon` is a real
            # account name, and the only strange thing about that row is a
            # trailing null on an otherwise readable username. It is an attempt
            # and it counts.
            #
            # The rule is now: an artefact is a row with NO READABLE CREDENTIAL
            # in it. The username must survive stripping -- it is the field a
            # bot chose, so if nothing readable is left there, nobody was trying
            # to log in. The password must survive only if it was non-empty to
            # begin with, because deliberately empty is meaningful and
            # unreadable is not.
            #
            # Exactly one row changed. Fixing it anyway: being right about one
            # row is the same discipline as being right about two hundred, and
            # the alternative is a rule I know to be wrong in a way I have
            # written down.
            # isprintable(), NOT an ASCII range test. This caught a bug during
            # regression testing on 29 September 2026: `32 <= ord(c) < 127`
            # rejects 'Ω', 'ö', Cyrillic and CJK, so a real password containing
            # any of them, in a field that also carried an escape, was labelled
            # binary. That is the SAME defect that was fixed hours earlier by
            # moving this test inside the escape branch -- reintroduced by the
            # fix above, and found only because the test suite asks about
            # 'root\x00' / 'Ω' explicitly.
            #
            # The test has to reject CONTROL BYTES, not non-ASCII characters.
            # Escapes are already gone by this point, so anything left is a
            # literal character somebody typed, and str.isprintable() is exactly
            # the question worth asking about it.
            def readable(value):
                return bool(value) and value.isprintable()

            # KNOWN LIMITATION, stated rather than papered over. A field made of
            # terminal control sequences -- '\x1b[A\x1b[B', the arrow keys --
            # strips to '[A[B', which IS printable, so this rule counts it as a
            # credential. No such row has been observed in this sensor's data;
            # the case was invented while testing, not found.
            #
            # It is deliberately not fixed. Adding a rule for a pattern nobody
            # has seen means writing a filter against imagination, and every bad
            # exclusion rule on this project began that way. The check is
            # instead written down as a standing query -- see weekly.sql, "login
            # rows that contain an escape and still count" -- so if it ever
            # appears it appears as data, and the rule gains a case with
            # evidence behind it.

            if not readable(su):
                return 'artefact-binary'
            if sp and not readable(sp):
                return 'artefact-binary'
            u_cmd = su.lower() in CONSOLE_WORDS or su.startswith('/bin/')
            p_cmd = sp.lower() in CONSOLE_WORDS or sp.startswith('/bin/')
            if u_cmd and p_cmd:
                return 'artefact-command'
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
    print('  arrivals, both doors    %d' % one(
        'SELECT COUNT(*) FROM v_arrivals')[0])
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
    print('  ARRIVALS by door and port -- not the same thing')
    for door, port, n, s_ in db.execute(
            'SELECT door, dst_port, COUNT(*), COUNT(DISTINCT src_ip) '
            'FROM v_arrivals GROUP BY 1, 2 ORDER BY 3 DESC'):
        print('    %-4s %-6s %7d events  %5d sources' % (door, port, n, s_))

    print()
    print('=== the OT door ===')
    rows = list(db.execute(
        "SELECT eventid, COUNT(*), COUNT(DISTINCT session), "
        "       COUNT(DISTINCT src_ip) "
        "FROM v_events WHERE eventid LIKE 'conpot.%' "
        "GROUP BY 1 ORDER BY 2 DESC"))
    if not rows:
        # Not the same as "nothing arrived". Before 6 October 2026 port 502 is
        # closed in both firewall layers, so an empty OT table is the expected
        # and correct state, and our own localhost testing is excluded as
        # loopback. Saying so here stops it reading as a broken pipeline.
        print('    no OT events that count')
        excl = db.execute(
            "SELECT COALESCE(excluded,'?'), COUNT(*) FROM events "
            "WHERE eventid LIKE 'conpot.%' GROUP BY 1 ORDER BY 2 DESC").fetchall()
        for reason, n in excl:
            print('      (%d excluded as %s)' % (n, reason))
    for eid, n, sess, srcs in rows:
        print('    %-30s %6d events  %4d sessions  %4d sources' % (eid, n, sess, srcs))

    print()
    print('=== excluded as an artefact, so the rule can be checked ===')
    rows = list(db.execute(
        "SELECT username, password, COUNT(*) FROM events "
        "WHERE excluded LIKE 'artefact%' GROUP BY 1, 2 ORDER BY 3 DESC"))
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

    # Both decoys, into one facts table. The IT log must exist -- if it does
    # not, something is wrong and the run should stop. The OT log may legitimately
    # be absent: Conpot was installed later, and on a machine where it is not
    # running yet there is nothing to read. Missing is reported, never silent,
    # because "no OT events" and "nobody looked at the OT log" are different
    # findings and this pipeline exists to keep them apart.
    sources = (('IT  cowrie', LOGS,    None,             True),
               ('OT  conpot', OT_LOGS, normalise_conpot, False))

    found = []
    for label, pattern, normaliser, required in sources:
        paths = sorted(glob.glob(pattern))
        if not paths and required:
            raise SystemExit('No log files matched %s' % pattern)
        found.append((label, pattern, paths, normaliser))

    db = sqlite3.connect(DB)
    with open(SCHEMA) as fh:
        db.executescript(fh.read())

    started = now()
    cur = db.cursor()
    cur.execute('INSERT INTO runs (started) VALUES (?)', (started,))
    run_id = cur.lastrowid

    read = inserted = skipped = rejected = 0

    # Flattened on purpose: one loop over (normaliser, path) pairs keeps the
    # line handling below at a single indent level instead of three.
    work = [(normaliser, path)
            for _label, _pattern, paths, normaliser in found
            for path in paths]

    for normaliser, path in work:
        with open(path, errors='replace') as fh:
            for line in fh:
                line = line.rstrip('\n')
                if not line.strip():
                    continue
                read += 1
                sha = hashlib.sha256(line.encode('utf-8', 'replace')).hexdigest()

                try:
                    record = json.loads(line)
                    if not isinstance(record, dict):
                        raise ValueError('not a JSON object')
                    e = normaliser(record) if normaliser else record
                    if not e.get('eventid') or not e.get('timestamp'):
                        raise ValueError('missing event type or timestamp')
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
    for label, pattern, paths, _normaliser in found:
        if paths:
            print('  %s  %s' % (label,
                                ', '.join(os.path.basename(p) for p in paths)))
        else:
            print('  %s  NOTHING MATCHED %s' % (label, pattern))
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
