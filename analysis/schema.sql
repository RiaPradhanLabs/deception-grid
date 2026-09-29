-- decoy.sqlite -- schema v1
-- Deception Grid, ReDI School capstone.
--
-- One table of facts. Nothing is deleted; exclusions are a labelled column,
-- so every excluded row stays countable and auditable.

PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS events (
  id        INTEGER PRIMARY KEY,
  line_sha  TEXT NOT NULL UNIQUE,   -- identity: lets ingest re-run safely
  ts        TEXT NOT NULL,          -- UTC, as Cowrie writes it
  eventid   TEXT NOT NULL,
  sensor    TEXT,
  session   TEXT,
  src_ip    TEXT,
  src_port  INTEGER,
  dst_port  INTEGER,
  username  TEXT,
  password  TEXT,
  input     TEXT,
  message   TEXT,
  raw       TEXT NOT NULL,          -- the whole original line, kept
  excluded  TEXT                    -- NULL = counts. Otherwise the reason.
);

CREATE INDEX IF NOT EXISTS ix_events_eventid ON events(eventid);
CREATE INDEX IF NOT EXISTS ix_events_src     ON events(src_ip);
CREATE INDEX IF NOT EXISTS ix_events_session ON events(session);
CREATE INDEX IF NOT EXISTS ix_events_excl    ON events(excluded);

-- Lines that would not parse at all. Kept verbatim rather than discarded.
-- line_sha is unique for the same reason as in `events`: a re-run must not
-- record the same bad line twice.
CREATE TABLE IF NOT EXISTS rejects (
  id        INTEGER PRIMARY KEY,
  line_sha  TEXT NOT NULL UNIQUE,
  seen      TEXT NOT NULL,
  line      TEXT NOT NULL,
  why       TEXT NOT NULL
);

-- One row per ingest run, so the pipeline has a history.
CREATE TABLE IF NOT EXISTS runs (
  id         INTEGER PRIMARY KEY,
  started    TEXT NOT NULL,
  finished   TEXT,
  lines_read INTEGER,
  inserted   INTEGER,
  skipped    INTEGER,
  rejected   INTEGER
);

-- Everything that counts. Query this, not `events`.
CREATE VIEW IF NOT EXISTS v_events AS
  SELECT * FROM events WHERE excluded IS NULL;

CREATE VIEW IF NOT EXISTS v_logins AS
  SELECT ts, session, src_ip, username, password,
         CASE WHEN eventid = 'cowrie.login.success' THEN 1 ELSE 0 END AS ok
    FROM events
   WHERE excluded IS NULL
     AND eventid IN ('cowrie.login.success', 'cowrie.login.failed');

-- ARRIVALS, both doors. This view exists because of a bug found on 29 September
-- 2026: every "arrivals" figure in the analysis filtered on
-- `eventid = 'cowrie.session.connect'`, which is the IT door only. Conpot names
-- its arrival `NEW_CONNECTION`, normalised here to `conpot.new_connection`. A
-- query titled "arrivals per door" that silently counts one door would have
-- reported the OT door as zero traffic for as long as anyone believed it.
--
-- Anything counting arrivals uses THIS view. Two event names, one definition, in
-- one place -- so adding a third decoy is one line here rather than a hunt
-- through the queries.
--
-- Note on `ts`: Cowrie writes `...Z`, Conpot writes `...+00:00`. Both are UTC
-- and both sort correctly against each other, because the date-and-time prefix
-- decides every comparison that matters. Only two events identical to the
-- microsecond could order oddly between the doors.
CREATE VIEW IF NOT EXISTS v_arrivals AS
  SELECT ts, session, src_ip, src_port, dst_port,
         CASE WHEN eventid LIKE 'conpot.%' THEN 'OT' ELSE 'IT' END AS door
    FROM events
   WHERE excluded IS NULL
     AND eventid IN ('cowrie.session.connect', 'conpot.new_connection');

-- The OT door. Conpot's records are normalised into the same `events` table by
-- ingest.py -- see normalise_conpot there for the field mapping and for why one
-- table rather than two. `eventid` always carries the 'conpot.' prefix, which is
-- what separates the doors; `sensor` says which decoy, and dst_port says which
-- port was knocked on. Never dst_ip: Azure translates, so it is always the
-- private address.
CREATE VIEW IF NOT EXISTS v_ot AS
  SELECT ts, session, src_ip, src_port, dst_port,
         substr(eventid, 8)                            AS event,
         -- `input`, not json_extract(raw,'$.request'): ingest.py has already
         -- unwrapped Conpot's "b'0001...'" bytes-repr into plain hex there.
         -- `response` is read from raw and still carries the wrapper, which is
         -- deliberate -- what the decoy replied is not a finding about the
         -- visitor, so it is kept verbatim rather than tidied.
         input                                         AS request,
         json_extract(raw, '$.response')               AS response,
         json_extract(raw, '$.data.function_code')     AS function_code,
         json_extract(raw, '$.data.slave_id')          AS slave_id,
         json_extract(raw, '$.session_time')           AS session_started
    FROM events
   WHERE excluded IS NULL
     AND eventid LIKE 'conpot.%';

CREATE VIEW IF NOT EXISTS v_commands AS
  SELECT ts, session, src_ip, input,
         CASE WHEN eventid = 'cowrie.command.input' THEN 1 ELSE 0 END AS ran
    FROM events
   WHERE excluded IS NULL
     AND eventid IN ('cowrie.command.input', 'cowrie.command.failed');
