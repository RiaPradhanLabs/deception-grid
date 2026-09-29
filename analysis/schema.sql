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

CREATE VIEW IF NOT EXISTS v_commands AS
  SELECT ts, session, src_ip, input,
         CASE WHEN eventid = 'cowrie.command.input' THEN 1 ELSE 0 END AS ran
    FROM events
   WHERE excluded IS NULL
     AND eventid IN ('cowrie.command.input', 'cowrie.command.failed');
