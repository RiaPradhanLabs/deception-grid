-- option4-telemetry.sql -- is there anything to predict FROM?
--
--   cd ~/analysis && sqlite3 -header -column decoy.sqlite < option4-telemetry.sql
--
-- Option 4 of the ML spin-off plan ("escalation prediction": from what a
-- session does BEFORE its login succeeds, predict whether it goes on to run
-- commands or move files) was parked on 5 October 2026 behind one question:
-- how many sessions carry enough pre-login telemetry to predict from? This
-- file answers it the way overlap-test.py answered the premise under options 2
-- and 5 -- measured on the data before any hours are committed.
--
-- Definitions, so the figures mean one thing:
--   a SESSION here is one that reached at least one cowrie.login.success;
--   PRE-LOGIN events are that session's rows strictly before its first success,
--     excluding the connect event itself (every session has one; it predicts
--     nothing);
--   ESCALATED means the session then produced at least one cowrie.command.input
--     or any file event (download, failed download, upload).
-- Pre-login telemetry Cowrie can record: client.version and client.kex (SSH
-- only -- telnet has neither), login.failed attempts, and client.size.
-- Excluded rows (analyst, loopback, artefact credentials) are out, as
-- everywhere else. Aggregates only; no address appears in any output.

.print === A. Sessions with a successful login, by door port ===
WITH s AS (
  SELECT session, dst_port, MIN(ts) AS t_ok
    FROM events
   WHERE excluded IS NULL AND eventid = 'cowrie.login.success'
   GROUP BY session
)
SELECT dst_port, COUNT(*) AS sessions
  FROM s GROUP BY 1 ORDER BY 1;

.print
.print === B. Pre-login events per session: how much is there to predict from? ===
WITH s AS (
  SELECT session, dst_port, MIN(ts) AS t_ok
    FROM events
   WHERE excluded IS NULL AND eventid = 'cowrie.login.success'
   GROUP BY session
),
pre AS (
  SELECT s.session, s.dst_port,
         SUM(e.ts < s.t_ok AND e.eventid NOT IN ('cowrie.session.connect','cowrie.login.success')) AS n_pre,
         SUM(e.ts < s.t_ok AND e.eventid = 'cowrie.client.version') AS n_version,
         SUM(e.ts < s.t_ok AND e.eventid = 'cowrie.client.kex')     AS n_kex,
         SUM(e.ts < s.t_ok AND e.eventid = 'cowrie.login.failed')   AS n_failed
    FROM s JOIN events e ON e.session = s.session AND e.excluded IS NULL
   GROUP BY s.session
)
SELECT dst_port,
       CASE WHEN n_pre = 0 THEN '0'
            WHEN n_pre = 1 THEN '1'
            WHEN n_pre = 2 THEN '2'
            WHEN n_pre <= 5 THEN '3-5'
            WHEN n_pre <= 10 THEN '6-10'
            ELSE '>10' END          AS pre_login_events,
       COUNT(*)                     AS sessions,
       SUM(n_kex > 0)               AS with_kex,
       SUM(n_version > 0)           AS with_version,
       SUM(n_failed > 0)            AS with_failed_attempt
  FROM pre
 GROUP BY 1, 2
 ORDER BY 1, MIN(n_pre);

.print
.print === C. Did they escalate? Base rate, and by how much pre-login telemetry existed ===
WITH s AS (
  SELECT session, dst_port, MIN(ts) AS t_ok
    FROM events
   WHERE excluded IS NULL AND eventid = 'cowrie.login.success'
   GROUP BY session
),
pre AS (
  SELECT s.session, s.dst_port,
         SUM(e.ts < s.t_ok AND e.eventid NOT IN ('cowrie.session.connect','cowrie.login.success')) AS n_pre,
         SUM(e.ts >= s.t_ok AND e.eventid = 'cowrie.command.input') AS n_cmd,
         SUM(e.ts >= s.t_ok AND (e.eventid LIKE 'cowrie.session.file_download%' OR e.eventid = 'cowrie.session.file_upload')) AS n_file
    FROM s JOIN events e ON e.session = s.session AND e.excluded IS NULL
   GROUP BY s.session
)
SELECT dst_port,
       CASE WHEN n_pre = 0 THEN '0'
            WHEN n_pre <= 2 THEN '1-2'
            WHEN n_pre <= 5 THEN '3-5'
            ELSE '>5' END                              AS pre_login_events,
       COUNT(*)                                        AS sessions,
       SUM(n_cmd > 0 OR n_file > 0)                    AS escalated,
       ROUND(100.0 * SUM(n_cmd > 0 OR n_file > 0) / COUNT(*), 1) AS pct_escalated,
       SUM(n_file > 0)                                 AS with_file_event
  FROM pre
 GROUP BY 1, 2
 ORDER BY 1, MIN(n_pre);

.print
.print === D. Which pre-login event types exist at all, and in how many sessions ===
WITH s AS (
  SELECT session, MIN(ts) AS t_ok
    FROM events
   WHERE excluded IS NULL AND eventid = 'cowrie.login.success'
   GROUP BY session
)
SELECT e.eventid, COUNT(*) AS events, COUNT(DISTINCT e.session) AS sessions
  FROM s JOIN events e ON e.session = s.session AND e.excluded IS NULL
 WHERE e.ts < s.t_ok
 GROUP BY 1 ORDER BY 3 DESC;

.print
.print --- Reading it: if most SSH sessions carry kex + version + at least one
.print --- failed attempt, option 4 has features. If the modal pre-login count is
.print --- 0 or 1 and escalation is near-universal or near-zero, there is nothing
.print --- to predict and option 4 is withdrawn like option 3 was.
