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
       (SELECT COUNT(*) FROM v_events
          WHERE eventid = 'cowrie.session.connect')           AS connections,
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
.print === 4. Arrivals per door. Connections, not events ===
SELECT dst_port,
       COUNT(*)                       AS connections,
       COUNT(DISTINCT src_ip)         AS distinct_sources
  FROM v_events
 WHERE eventid = 'cowrie.session.connect'
 GROUP BY 1
 ORDER BY 2 DESC;

.print
.print === 5. Arrivals per day. Is the rate changing? ===
SELECT substr(ts, 1, 10)              AS day,
       COUNT(*)                       AS connections,
       COUNT(DISTINCT src_ip)         AS distinct_sources
  FROM v_events
 WHERE eventid = 'cowrie.session.connect'
 GROUP BY 1
 ORDER BY 1;

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
SELECT src_ip,
       COUNT(*)                   AS connections,
       substr(MIN(ts), 1, 16)     AS first_seen,
       substr(MAX(ts), 1, 16)     AS last_seen
  FROM v_events
 WHERE eventid = 'cowrie.session.connect'
 GROUP BY 1
 ORDER BY 2 DESC
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
.print === 12. Files: fetched by us, or supplied by them? ===
-- This distinction produced five wrong figures on 29 September 2026 and is the
-- reason this query exists. Cowrie logs three different things under the single
-- eventid cowrie.session.file_download. Only a `url` means an outbound fetch:
--
--   url present            we went and got it. OUTBOUND. Must be zero for any
--                          timestamp after the block went in on 29 Sept 12:00.
--   file_upload, no url    the attacker pushed it over scp. Inbound.
--   file_download, no url  a shell redirection we captured. Inbound, and not
--                          delivery at all -- it is the writable-directory
--                          probe, which is why it yields few distinct files
--                          from many events.
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
.print === 13. Registration country of the busiest sources ===
-- Needs geo.sqlite, built by ./geo-lookup.sh. If that file does not exist yet
-- this query reports "no such table: g.geo" and stops there; queries 1 to 11
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
             (SELECT COUNT(*) FROM v_events
               WHERE eventid = 'cowrie.session.connect'), 1) AS pct_of_all
  FROM v_events e
  JOIN g.geo ON g.geo.src_ip = e.src_ip
 WHERE e.eventid = 'cowrie.session.connect'
 GROUP BY 1
 ORDER BY 2 DESC;
.print
