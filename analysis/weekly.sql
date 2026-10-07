-- weekly.sql -- the standing questions, so they are never retyped.
--
--   cd ~/analysis && sqlite3 -header -column decoy.sqlite < weekly.sql
--
-- Every query reads v_events or v_logins, which exclude our own traffic and
-- the mis-recorded credentials. To see what was excluded and why, query the
-- `events` table directly -- nothing is deleted, only labelled.

.print
.print === 1. Has the pipeline been running? ===
SELECT id,
       substr(started, 1, 16)  AS started_utc,
       lines_read,
       inserted                AS new_rows,
       rejected                AS unparseable
  FROM runs
 ORDER BY id DESC
 LIMIT 5;

.print
.print === 2. Headline figures. Lead with distinct sources, never events ===
SELECT (SELECT COUNT(DISTINCT src_ip) FROM v_events
          WHERE src_ip IS NOT NULL)                          AS distinct_sources,
       (SELECT COUNT(*) FROM v_arrivals)                      AS arrivals_both_doors,
       (SELECT COUNT(*) FROM v_logins)                        AS password_attempts,
       (SELECT COUNT(*) FROM v_logins WHERE ok = 1)           AS successes,
       (SELECT COUNT(DISTINCT src_ip) FROM v_logins
          WHERE ok = 1)                                       AS sources_that_got_in,
       (SELECT substr(MIN(ts), 1, 16) FROM v_events)          AS first_event,
       (SELECT substr(MAX(ts), 1, 16) FROM v_events)          AS last_event;

.print
.print === 3. What is excluded, and why. State this alongside any figure ===
SELECT COALESCE(excluded, '(counts)') AS reason,
       COUNT(*)                       AS rows
  FROM events
 GROUP BY 1
 ORDER BY 2 DESC;

.print
.print === 4. Arrivals per door. Arrivals, not events ===
-- v_arrivals, not v_events: it counts BOTH doors. An earlier version of this
-- query filtered on cowrie.session.connect alone and would have reported the OT
-- door as having no traffic at all.
SELECT door,
       dst_port,
       COUNT(*)                       AS arrivals,
       COUNT(DISTINCT src_ip)         AS distinct_sources
  FROM v_arrivals
 GROUP BY 1, 2
 ORDER BY 3 DESC;

.print
.print === 5. Arrivals per day, per door. Is the rate changing? ===
SELECT substr(ts, 1, 10)              AS day,
       door,
       COUNT(*)                       AS arrivals,
       COUNT(DISTINCT src_ip)         AS distinct_sources
  FROM v_arrivals
 GROUP BY 1, 2
 ORDER BY 1, 2;

.print
.print === 6. Most-tried credentials ===
SELECT username, password, COUNT(*) AS tries
  FROM v_logins
 GROUP BY 1, 2
 ORDER BY 3 DESC
 LIMIT 15;

.print
.print === 7. Credentials that actually worked. This is the recommendation ===
SELECT username, password,
       COUNT(*)               AS successes,
       COUNT(DISTINCT src_ip) AS from_sources
  FROM v_logins
 WHERE ok = 1
 GROUP BY 1, 2
 ORDER BY 3 DESC;

.print
.print === 8. Busiest sources by ARRIVALS, not by events ===
-- group_concat(DISTINCT door) shows anyone who tried BOTH doors from one
-- address. That is the single most interesting row this project can produce, so
-- it must not be hidden by counting the doors separately.
SELECT src_ip,
       group_concat(DISTINCT door) AS doors,
       COUNT(*)                   AS arrivals,
       substr(MIN(ts), 1, 16)     AS first_seen,
       substr(MAX(ts), 1, 16)     AS last_seen
  FROM v_arrivals
 GROUP BY 1
 ORDER BY 3 DESC
 LIMIT 10;

.print
.print === 9. What they typed once inside, and whether it worked ===
-- Cowrie logs each command twice: cowrie.command.input carries the raw line
-- (with its trailing space) and cowrie.command.failed carries the parsed word.
-- Summing both double-counts every command, which an earlier version of this
-- query did. trim() collapses the pair; the two columns keep them apart.
-- When `typed` and `failed` are equal, every attempt at that command failed --
-- which is the quantified form of "no payload was ever delivered".
SELECT trim(input)                AS command,
       SUM(ran)                   AS typed,
       SUM(1 - ran)               AS failed,
       COUNT(DISTINCT session)    AS sessions
  FROM v_commands
 WHERE input IS NOT NULL
   AND trim(input) <> ''
 GROUP BY 1
 ORDER BY 2 DESC
 LIMIT 15;

.print
.print === 10. Attempts to use us as a proxy. Every one must say discarded ===
SELECT src_ip, dst_port,
       COUNT(*)                   AS events,
       substr(MIN(ts), 1, 16)     AS first_seen,
       substr(MAX(ts), 1, 16)     AS last_seen
  FROM v_events
 WHERE eventid LIKE 'cowrie.direct-tcpip%'
 GROUP BY 1, 2
 ORDER BY 3 DESC;

.print
.print === 11. Anything the parser could not read. Should be empty ===
SELECT substr(seen, 1, 16) AS seen, why, substr(line, 1, 60) AS line_start
  FROM rejects
 ORDER BY id DESC
 LIMIT 10;

.print
.print === 12. Login rows that contain an escape and still count ===
-- The audit trail for the artefact rule. Every row here carries a \xNN escape
-- and was judged a REAL attempt anyway, so this is the list to read when asking
-- whether the rule is too permissive -- the counterpart to query 3, which shows
-- what it threw out.
--
-- Read it rather than trusting the total. Two of the three versions of that rule
-- were wrong, and both were caught by looking at rows instead of counts.
--
-- Anything that looks like terminal control -- values beginning '[A', '[B', '[C'
-- or '[' followed by a digit -- is the known limitation recorded in ingest.py
-- and has never yet appeared. If it shows up here, the rule gains a case with
-- evidence behind it.
SELECT username, password, COUNT(*) AS rows_
  FROM v_events
 WHERE eventid IN ('cowrie.login.success', 'cowrie.login.failed')
   AND (username LIKE '%\x%' OR password LIKE '%\x%')
 GROUP BY 1, 2
 ORDER BY 3 DESC
 LIMIT 20;

.print
.print === 13. Files: fetched by us, or supplied by them? ===
-- This distinction produced five wrong figures on 29 September 2026 and is the
-- reason this query exists. Cowrie logs FOUR different things under eventids
-- beginning cowrie.session.file_, and a `url` alone does not separate them:
--
--   file_download, url, and a shasum or outfile
--                          we went and got it, and we GOT it. OUTBOUND, and
--                          this is the one that must be zero for any timestamp
--                          after the block went in on 29 Sept 12:00.
--   file_download.failed, url
--                          we tried and were STOPPED. Outbound in intent,
--                          inbound in effect: nothing arrived. Expected to be
--                          large and growing -- it is the block working, and it
--                          is evidence the control is alive rather than a
--                          breach. 505 of these by 5 October, 34 destinations.
--   file_upload, no url    the attacker pushed it over scp. Inbound.
--   file_download, no url  a shell redirection we captured. Inbound, and not
--                          delivery at all -- it is the writable-directory
--                          probe, which is why it yields few distinct files
--                          from many events.
--
-- CORRECTED 5 October 2026, and the correction is the point. The four lines
-- above previously read "url present -- we went and got it. OUTBOUND. Must be
-- zero", which is wrong, because a BLOCKED fetch is logged as
-- file_download.failed and carries the url it tried. The SELECT below always
-- had this right: it tests the eventid as well as the url, and reports "FETCHED
-- - outbound" separately from "fetch failed - outbound".
--
-- analysis/figures.sh then implemented the COMMENT rather than the query four
-- lines below it, and so reported 455 blocked attempts as *** THE BLOCK IS NOT
-- HOLDING *** on every run since 29 September, with the instruction not to
-- publish any figure until it was explained. A correct implementation with a
-- wrong prose summary beside it is more dangerous than no summary, because the
-- next thing built is built from the prose.
--
-- Never count these together, and never count files in the downloads directory
-- as a proxy for any of them: redirection captures are named redir_<uuid>
-- rather than by hash, so that directory holds more files than distinct content.
SELECT CASE
         WHEN eventid = 'cowrie.session.file_upload'          THEN 'pushed over scp'
         WHEN json_extract(raw, '$.url') IS NOT NULL
              AND eventid = 'cowrie.session.file_download'    THEN 'FETCHED - outbound'
         WHEN json_extract(raw, '$.url') IS NOT NULL          THEN 'fetch failed - outbound'
         ELSE 'shell redirection'
       END                                      AS kind,
       COUNT(*)                                 AS events,
       COUNT(DISTINCT session)                  AS sessions,
       COUNT(DISTINCT json_extract(raw, '$.shasum')) AS distinct_files,
       substr(MAX(ts), 1, 16)                   AS last_seen
  FROM v_events
 WHERE eventid LIKE 'cowrie.session.file_%'
 GROUP BY 1
 ORDER BY 2 DESC;

.print
.print === 14. The OT door: has anything arrived, and what did it ask for? ===
-- Empty is the CORRECT answer before 6 October 2026: port 502 is closed in both
-- firewall layers until then, and our own localhost testing is excluded as
-- loopback. Empty AFTER that date means either nothing arrived or the decoy
-- stopped recording, and those are different problems -- check query 1 and
-- `systemctl is-active conpot` before concluding anything.
SELECT event,
       COUNT(*)                   AS events,
       COUNT(DISTINCT session)    AS sessions,
       COUNT(DISTINCT src_ip)     AS sources,
       substr(MIN(ts), 1, 16)     AS first_seen,
       substr(MAX(ts), 1, 16)     AS last_seen
  FROM v_ot
 GROUP BY 1
 ORDER BY 2 DESC;

.print
.print === 15. OT: which Modbus function codes were requested ===
-- The finding is WHAT was asked for, not that a connection happened. Function 3
-- or 4 is a read: reconnaissance. Function 5, 6, 15 or 16 is a WRITE -- an
-- attempt to change a coil or a register, which on real plant is an attempt to
-- operate it. Function 43 is Read Device Identification: vendor fingerprinting;
-- 17 is Report Server ID, the older serial-line form of the same question.
-- 17 was labelled 'other / unhandled' until 7 October 2026, when the first
-- stranger to use it arrived; the count was right, the label was not.
SELECT function_code,
       CASE function_code
         WHEN  1 THEN 'read coils'
         WHEN  2 THEN 'read discrete inputs'
         WHEN  3 THEN 'read holding registers'
         WHEN  4 THEN 'read input registers'
         WHEN  5 THEN 'WRITE single coil'
         WHEN  6 THEN 'WRITE single register'
         WHEN 15 THEN 'WRITE multiple coils'
         WHEN 16 THEN 'WRITE multiple registers'
         WHEN 17 THEN 'report server id'
         WHEN 43 THEN 'read device identification'
         ELSE        'other / unhandled'
       END                        AS meaning,
       COUNT(*)                   AS requests,
       COUNT(DISTINCT src_ip)     AS sources
  FROM v_ot
 WHERE function_code IS NOT NULL
 GROUP BY 1, 2
 ORDER BY 3 DESC;

.print
.print === 16. The comparison this project exists to make: IT door vs OT door ===
-- One machine, one address, two doors. Quote distinct sources, never events.
-- The denominators differ: the IT door has been open since 25 September, the OT
-- door opens 6 October. State both dates alongside this table, or it reads as a
-- like-for-like count when it is not.
SELECT CASE WHEN eventid LIKE 'conpot.%' THEN 'OT  (Modbus)'
            ELSE 'IT  (SSH/telnet)' END       AS door,
       COUNT(DISTINCT src_ip)                 AS distinct_sources,
       COUNT(DISTINCT session)                AS sessions,
       COUNT(*)                               AS events,
       substr(MIN(ts), 1, 10)                 AS first_day,
       substr(MAX(ts), 1, 10)                 AS last_day
  FROM v_events
 GROUP BY 1
 ORDER BY 2 DESC;

.print
.print === 18. Both doors: had the OT visitors already been to the IT door? ===
-- The README's argument -- same scanners, same country, same minute, and the
-- only difference between the doors is the door -- is a claim about the SAME
-- sources turning up at both. Nothing measured that before 7 October 2026, so
-- docs/first-ot-hours.md declined to say it. This is the query that asks.
-- gap_days is from a source's first IT arrival to its first OT arrival;
-- negative means it found the OT door first. Aggregates only: no address is
-- printed, by the rules of engagement. The 19-character prefix of ts is used
-- because Cowrie writes '...Z' and Conpot '...+00:00'; both are UTC.
WITH ot AS (SELECT src_ip, MIN(substr(ts, 1, 19)) AS first_ot
              FROM v_arrivals WHERE door = 'OT' GROUP BY 1),
     it AS (SELECT src_ip, MIN(substr(ts, 1, 19)) AS first_it
              FROM v_arrivals WHERE door = 'IT' GROUP BY 1)
SELECT COUNT(*)                                            AS ot_sources,
       COUNT(it.src_ip)                                    AS also_at_it_door,
       ROUND(100.0 * COUNT(it.src_ip) / MAX(COUNT(*), 1), 1) AS pct,
       ROUND(MIN(julianday(ot.first_ot) - julianday(it.first_it)), 1) AS gap_days_min,
       ROUND(MAX(julianday(ot.first_ot) - julianday(it.first_it)), 1) AS gap_days_max
  FROM ot LEFT JOIN it USING (src_ip);

.print
.print === 19. OT: return visits -- connections per source, as a distribution ===
-- 14 connections from 11 sources in the first fourteen hours meant three return
-- visits, and nothing showed which. This shows the shape without naming anyone:
-- how many sources came once, how many twice, and so on.
SELECT visits, COUNT(*) AS sources
  FROM (SELECT src_ip, COUNT(*) AS visits
          FROM v_arrivals WHERE door = 'OT' GROUP BY 1)
 GROUP BY 1
 ORDER BY 1;

.print
.print === 17. Registration country of the busiest sources ===
-- Needs geo.sqlite, built by ./geo-lookup.sh. If that file does not exist yet
-- this query reports "no such table: g.geo" and stops there; queries 1 to 16
-- above are unaffected, and ATTACH leaves an empty geo.sqlite behind which
-- geo-lookup.sh then fills. Untidy but harmless, and honest about it.
-- Registration, not location: whois says who was allocated the address block.
-- Renting a server costs a few euros a month from anywhere, so this says where
-- traffic arrived from and nothing about who sent it. Quote the coverage figure
-- with the table -- percentages are of ALL arrivals and will not sum to 100,
-- because the sources never looked up are the remainder.
ATTACH DATABASE 'geo.sqlite' AS g;
SELECT g.geo.cc                  AS country,
       COUNT(*)                  AS arrivals,
       COUNT(DISTINCT e.src_ip)  AS sources,
       ROUND(100.0 * COUNT(*) /
             (SELECT COUNT(*) FROM v_arrivals), 1) AS pct_of_all
  FROM v_arrivals e
  JOIN g.geo ON g.geo.src_ip = e.src_ip
 GROUP BY 1
 ORDER BY 2 DESC;
.print
