-- option4-clients.sql -- M3: do the SSH clients that get in differ at all?
--
--   cd ~/analysis && sqlite3 -header -column decoy.sqlite < option4-clients.sql
--
-- option4-telemetry.sql (M2, 9 October 2026) narrowed ML option 4 to SSH: every
-- SSH session that reaches a successful login carries a client version string
-- and a key-exchange record BEFORE the login. Those are the prefix features. This
-- file asks the last question before any hours go in: do the values VARY, and
-- does the outcome vary with them? If 650 of 672 sessions present the same
-- client, there is nothing to learn from the prefix and option 4 is withdrawn.
--
-- Definitions as in option4-telemetry.sql: a session is one with at least one
-- cowrie.login.success on port 22; pre-login = before its first success;
-- ESCALATED = at least one command or file event afterwards. The version string
-- is what the client announced (e.g. the library name); HASSH is Cowrie's MD5
-- over the client's key-exchange algorithm lists -- a software fingerprint that
-- survives a change of announced version. Neither is an address or a credential.
-- Aggregates only.

.print === A. Summary: how many distinct clients, and how concentrated ===
WITH s AS (
  SELECT session, MIN(ts) AS t_ok FROM events
   WHERE excluded IS NULL AND eventid = 'cowrie.login.success' AND dst_port = 22
   GROUP BY session
),
ver AS (
  SELECT e.session, MIN(json_extract(e.raw, '$.version')) AS version
    FROM s JOIN events e ON e.session = s.session
   WHERE e.excluded IS NULL AND e.eventid = 'cowrie.client.version' AND e.ts < s.t_ok
   GROUP BY e.session
),
kex AS (
  SELECT e.session, MIN(json_extract(e.raw, '$.hassh')) AS hassh
    FROM s JOIN events e ON e.session = s.session
   WHERE e.excluded IS NULL AND e.eventid = 'cowrie.client.kex' AND e.ts < s.t_ok
   GROUP BY e.session
),
top AS (
  SELECT COUNT(*) AS n FROM ver GROUP BY version ORDER BY n DESC LIMIT 1
),
toph AS (
  SELECT COUNT(*) AS n FROM kex GROUP BY hassh ORDER BY n DESC LIMIT 1
)
SELECT (SELECT COUNT(*) FROM s)                       AS ssh_sessions,
       (SELECT COUNT(DISTINCT version) FROM ver)      AS distinct_versions,
       (SELECT n FROM top)                            AS sessions_with_top_version,
       (SELECT COUNT(DISTINCT hassh) FROM kex)        AS distinct_hassh,
       (SELECT n FROM toph)                           AS sessions_with_top_hassh,
       (SELECT COUNT(DISTINCT version || '|' || hassh)
          FROM ver JOIN kex USING (session))          AS distinct_version_hassh_pairs;

.print
.print === B. Client version strings, with escalation per value (top 15) ===
WITH s AS (
  SELECT session, MIN(ts) AS t_ok FROM events
   WHERE excluded IS NULL AND eventid = 'cowrie.login.success' AND dst_port = 22
   GROUP BY session
),
ver AS (
  SELECT e.session, MIN(json_extract(e.raw, '$.version')) AS version
    FROM s JOIN events e ON e.session = s.session
   WHERE e.excluded IS NULL AND e.eventid = 'cowrie.client.version' AND e.ts < s.t_ok
   GROUP BY e.session
),
post AS (
  SELECT s.session,
         SUM(e.ts >= s.t_ok AND e.eventid = 'cowrie.command.input') AS n_cmd,
         SUM(e.ts >= s.t_ok AND (e.eventid LIKE 'cowrie.session.file_download%' OR e.eventid = 'cowrie.session.file_upload')) AS n_file,
         SUM(e.ts <  s.t_ok AND e.eventid = 'cowrie.login.failed') AS n_failed
    FROM s JOIN events e ON e.session = s.session AND e.excluded IS NULL
   GROUP BY s.session
)
SELECT version,
       COUNT(*)                                   AS sessions,
       COUNT(DISTINCT e2.src_ip)                  AS sources,
       SUM(n_cmd > 0 OR n_file > 0)               AS escalated,
       ROUND(100.0 * SUM(n_cmd > 0 OR n_file > 0) / COUNT(*), 1) AS pct_escalated,
       SUM(n_file > 0)                            AS with_file_event,
       SUM(n_failed > 0)                          AS failed_first
  FROM ver JOIN post USING (session)
  JOIN (SELECT session, MIN(src_ip) AS src_ip FROM events WHERE excluded IS NULL AND eventid = 'cowrie.login.success' GROUP BY session) e2 USING (session)
 GROUP BY 1 ORDER BY 2 DESC LIMIT 15;

.print
.print === C. HASSH fingerprints, with escalation per value (top 15) ===
WITH s AS (
  SELECT session, MIN(ts) AS t_ok FROM events
   WHERE excluded IS NULL AND eventid = 'cowrie.login.success' AND dst_port = 22
   GROUP BY session
),
kex AS (
  SELECT e.session, MIN(json_extract(e.raw, '$.hassh')) AS hassh
    FROM s JOIN events e ON e.session = s.session
   WHERE e.excluded IS NULL AND e.eventid = 'cowrie.client.kex' AND e.ts < s.t_ok
   GROUP BY e.session
),
post AS (
  SELECT s.session,
         SUM(e.ts >= s.t_ok AND e.eventid = 'cowrie.command.input') AS n_cmd,
         SUM(e.ts >= s.t_ok AND (e.eventid LIKE 'cowrie.session.file_download%' OR e.eventid = 'cowrie.session.file_upload')) AS n_file
    FROM s JOIN events e ON e.session = s.session AND e.excluded IS NULL
   GROUP BY s.session
)
SELECT hassh,
       COUNT(*)                                   AS sessions,
       SUM(n_cmd > 0 OR n_file > 0)               AS escalated,
       ROUND(100.0 * SUM(n_cmd > 0 OR n_file > 0) / COUNT(*), 1) AS pct_escalated,
       SUM(n_file > 0)                            AS with_file_event
  FROM kex JOIN post USING (session)
 GROUP BY 1 ORDER BY 2 DESC LIMIT 15;

.print
.print === D. Version x HASSH: does the fingerprint split what the string lumps together? ===
WITH s AS (
  SELECT session, MIN(ts) AS t_ok FROM events
   WHERE excluded IS NULL AND eventid = 'cowrie.login.success' AND dst_port = 22
   GROUP BY session
),
ver AS (
  SELECT e.session, MIN(json_extract(e.raw, '$.version')) AS version
    FROM s JOIN events e ON e.session = s.session
   WHERE e.excluded IS NULL AND e.eventid = 'cowrie.client.version' AND e.ts < s.t_ok
   GROUP BY e.session
),
kex AS (
  SELECT e.session, MIN(json_extract(e.raw, '$.hassh')) AS hassh
    FROM s JOIN events e ON e.session = s.session
   WHERE e.excluded IS NULL AND e.eventid = 'cowrie.client.kex' AND e.ts < s.t_ok
   GROUP BY e.session
)
SELECT version, COUNT(DISTINCT hassh) AS distinct_hassh, COUNT(*) AS sessions
  FROM ver JOIN kex USING (session)
 GROUP BY 1 ORDER BY 3 DESC LIMIT 10;

.print
.print --- Reading it: option 4 has a prefix worth modelling if A shows several
.print --- values with real mass AND B or C show escalation rates that differ by
.print --- value. One value holding ~95% of sessions, or every value escalating
.print --- at the same rate, means the prefix carries no signal: withdraw.
