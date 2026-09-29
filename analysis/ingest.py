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
import gzip
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


BYTES_REPR = re.compile(r"^b(['\"])(.*)\1$", re.S)


def unwrap_bytes_repr(value):
    """Turn Conpot's "b'0001...'" into 0001...

    Conpot stores the Modbus request and response as a Python bytes REPR inside
    a JSON string, so the log literally contains the characters b, ', then the
    hex, then '. Left alone, every consumer has to strip that before it can
    decode a frame, and sooner or later one of them forgets and compares
    "b'0103'" against "0103".

    Normalised on the way in rather than at every point of use. `raw` keeps the
    original string untouched, so nothing is lost and the transformation is
    auditable. Anything not matching the pattern is returned unchanged -- if a
    future Conpot writes plain hex, this becomes a no-op rather than a bug.
    """
    if not isinstance(value, str):
        return value
    match = BYTES_REPR.match(value.strip())
    return match.group(2) if match else value


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

    # event_type is NULL on exactly the records that matter. Verified against
    # the live log on 29 September 2026: NEW_CONNECTION and CONNECTION_LOST
    # carry it, and the protocol records -- the ones holding slave_id and
    # function_code -- have `"event_type": null` and no other field naming the
    # event. Without a fallback every Modbus request would be recorded as
    # `conpot.none`, which is to say the most interesting events at the OT door
    # would all share one meaningless label.
    #
    # An earlier key census missed this because it counted whether the KEY was
    # present. It is present in every record; the value is null. Counting keys
    # is not reading values.
    event_type = event.get('event_type')
    if not event_type:
        event_type = ('%s_request' % (event.get('protocol') or 'unknown')
                      if event.get('request') is not None else 'unknown')

    return {
        'timestamp': event.get('event_time'),
        'eventid':   'conpot.' + str(event_type).lower(),
        'sensor':    event.get('sensorid'),
        'session':   event.get('session_id'),
        'src_ip':    event.get('src_ip'),
        'src_port':  event.get('src_port'),
        'dst_port':  event.get('dst_port'),
        'username':  None,
        'password':  None,
        'input':     unwrap_bytes_repr(event.get('request')),
        'message':   json.dumps(data, sort_keys=True) if data else None,
    }


def open_log(path):
    """Open a log file, transparently handling a compressed rotation.

    ingest.py globs `*.json*`, which matches a rotated `conpot.json.1` and also
    a compressed `conpot.json.1.gz`. Opened as text, a gzip file yields binary
    noise that fails to parse -- so every line would land in `rejects` and the
    day's data would be quietly absent from every figure.

    The logrotate config written on 29 September 2026 sets `nocompress` for
    exactly this reason. This function exists so that changing that setting -- by
    anyone, at any point, for a good reason -- cannot lose data. Two independent
    defences rather than a comment asking to be remembered.
    """
    if path.endswith('.gz'):
        return gzip.open(path, 'rt', errors='replace')
    return open(path, errors='replace')


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

            # A field made of terminal control sequences -- '\x1b\x11ECFF' --
            # strips to 'ECFF', which IS printable. When this was first written
            # the case was hypothetical and was deliberately left unhandled, on
            # the grounds that filtering against an imagined pattern is how the
            # earlier versions of this rule went wrong.
            #
            # It then turned up in the real data within the hour. The handling
            # below is therefore evidence-driven, and the standing query that
            # surfaced it -- weekly.sql, "login rows that contain an escape and
            # still count" -- stays, because it is what found this one.

            # Version five. The discriminator is whether the password field was
            # EMPTY IN THE LOG, not whether it is empty after stripping. Version
            # four tested `sp`, the stripped value, which collapses two cases
            # that the data shows are different:
            #
            #   'daemon\x00'      ''                      -> REAL
            #   '\x1b\x11ECFF'    '\x1b\x13\x04\x1a\x1f\x18' -> ARTEFACT
            #
            # Both have a username that survives stripping. In the first the
            # password field is genuinely empty, which is an ordinary probe. In
            # the second it was full of control bytes that stripped away to
            # nothing -- the terminal-control case recorded above as a "known
            # limitation that has never appeared". It had appeared: twice, in
            # this sensor's own data, and only reading the excluded rows found
            # it. Written down because it is the fourth time on this project
            # that a rule was wrong and the rows, not the totals, said so.
            if not readable(su):
                return 'artefact-binary'
            if (pw or '') != '' and not readable(sp):
                return 'artefact-binary'
            u_cmd = su.lower() in CONSOLE_WORDS or su.startswith('/bin/')
            p_cmd = sp.lower() in CONSOLE_WORDS or sp.startswith('/bin/')
            if u_cmd and p_cmd:
                return 'artefact-command'
    return None


DERIVED = ('ts', 'eventid', 'sensor', 'session', 'src_ip', 'src_port',
           'dst_port', 'username', 'password', 'input', 'message', 'excluded')


def rederive(db, own):
    """Recompute EVERY derived column for every row, from `raw`.

    This exists because of a bug found twice on 29 September 2026, the second
    time as the general case of the first.

    Every column except `raw` is DERIVED -- computed when the row was inserted.
    `INSERT OR IGNORE` never touches a row it already holds, so changing the
    code that computes those columns changed nothing already in the database.

    The narrow version bit first: narrowing the artefact rule relabelled NOTHING,
    and the only way to notice was to read the excluded list and see a row the
    current rule would have admitted. That was fixed by recomputing `excluded`.

    The general version bit an hour later. Conpot's `event_type` is null on its
    protocol records, so those rows had been labelled `conpot.none`; the fix
    synthesised `conpot.modbus_request` instead. New rows got the new label and
    the old rows kept `conpot.none` -- along with an `input` column still holding
    Conpot's "b'0001...'" bytes-repr, because that unwrapping is derived too.
    Recomputing one column had fixed one column.

    So this recomputes ALL of them. `raw` is the only authority in the database;
    everything else is a cache of what the current code makes of it. A row's
    identity stays its line_sha, so nothing is duplicated and the `runs` history
    survives -- which rebuilding from the logs would have discarded, and that
    history is the evidence the pipeline has been running.

    Which normaliser applies is decided by the record's SHAPE, not by the stored
    eventid: a Cowrie record has `eventid`, a Conpot record does not. Trusting
    the stored label here would mean trusting the value being recomputed.

    Prints what changed, per column. A silent re-derivation would be the same
    class of problem as the bug it fixes.
    """
    columns = ', '.join(DERIVED)
    changed_cols = {}
    transitions = {}
    updates = []

    for row in db.execute('SELECT id, raw, %s FROM events' % columns):
        row_id, raw = row[0], row[1]
        current = dict(zip(DERIVED, row[2:]))
        try:
            record = json.loads(raw)
        except Exception:
            continue

        event = record if 'eventid' in record else normalise_conpot(record)
        fresh = {
            'ts':       event.get('timestamp'),
            'eventid':  event.get('eventid'),
            'sensor':   event.get('sensor'),
            'session':  event.get('session'),
            'src_ip':   event.get('src_ip'),
            'src_port': event.get('src_port'),
            'dst_port': event.get('dst_port'),
            'username': event.get('username'),
            'password': event.get('password'),
            'input':    event.get('input'),
            'message':  event.get('message'),
            'excluded': exclusion_reason(event, own),
        }

        differing = [c for c in DERIVED if fresh[c] != current[c]]
        if not differing:
            continue
        for c in differing:
            changed_cols[c] = changed_cols.get(c, 0) + 1
        if 'eventid' in differing:
            key = '%s -> %s' % (current['eventid'], fresh['eventid'])
            transitions[key] = transitions.get(key, 0) + 1
        if 'excluded' in differing:
            key = '%s -> %s' % (current['excluded'] or '(counts)',
                                fresh['excluded'] or '(counts)')
            transitions[key] = transitions.get(key, 0) + 1
        updates.append(tuple(fresh[c] for c in DERIVED) + (row_id,))

    if updates:
        db.executemany(
            'UPDATE events SET %s WHERE id = ?'
            % ', '.join('%s = ?' % c for c in DERIVED), updates)
        db.commit()

    print()
    print('=== re-derived from raw against the current code ===')
    if not updates:
        print('    nothing changed -- the database already matches the code')
    else:
        print('    %d rows updated' % len(updates))
        for c, n in sorted(changed_cols.items(), key=lambda kv: -kv[1]):
            print('      column %-10s %6d rows' % (c, n))
        for key, n in sorted(transitions.items(), key=lambda kv: -kv[1]):
            print('      %-44s %6d' % (key, n))
    return len(updates)


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
        with open_log(path) as fh:
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

    rederive(db, own)
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
