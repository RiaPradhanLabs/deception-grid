#!/bin/bash
# figures.sh -- every figure the write-up quotes, freshly derived, in one place.
#
#   cd ~/analysis && sudo ./figures.sh
#
# Why this exists. Figures in this project are quoted across seven documents and
# a slide deck, and they move while the sensor runs. The plan was always "one
# refresh pass before the demo", which only works if the pass is mechanical --
# otherwise it is a hunt through prose, done under time pressure, which is how
# five wrong numbers got published on 29 September 2026.
#
# It refreshes the database first, so nothing here can be stale relative to the
# logs. Then it prints the figures with an explicit AS-OF line, and finally a map
# of which document carries which figure, so updating is transcription rather
# than search.
#
# It does NOT edit any document. Deliberately: a script that rewrites prose would
# have to understand the sentences around the numbers, and the one thing this
# project has learned repeatedly is that a figure without its caveat is worse
# than no figure.
set -u

cd "$(dirname "$0")"

AS_OF=$(date -u '+%Y-%m-%d %H:%M UTC')

echo
echo "================================================================"
echo "  DECEPTION GRID -- figures as at $AS_OF"
echo "================================================================"
echo
echo "  Every number below carries this timestamp. Quote the timestamp with"
echo "  the figure: these grow while the sensor is running, and an earlier"
echo "  snapshot is not wrong, it is earlier."
echo

# --- 1. refresh, so nothing is stale relative to the logs ----------------
echo "--- refreshing the database ------------------------------------"
python3 ingest.py | sed -n '/this run/,/would not parse/p;/re-derived/,/^$/p'

# --- 2. the standing questions ------------------------------------------
echo
echo "--- the standing questions (weekly.sql) ------------------------"
sqlite3 -header -column decoy.sqlite < weekly.sql 2>&1 \
  | grep -v 'no such table: g.geo'

# --- 3. figures that are not in the database ----------------------------
# Two of the most-quoted numbers are about files on disk, not rows, and the
# gap between them is itself a finding -- captured files exceed distinct
# content because redirection captures are named redir_<uuid> rather than by
# hash. Quoting either alone invites the wrong conclusion.
echo
echo "--- files on disk, which the database cannot tell you ----------"
DL=/home/cowrie/cowrie/var/lib/cowrie/downloads
if [ -d "$DL" ]; then
  n=$(find "$DL" -maxdepth 1 -type f ! -name '.gitignore' | wc -l)
  echo "  files held in downloads/          $n"
else
  echo "  downloads directory not readable -- run with sudo"
fi
d=$(sqlite3 decoy.sqlite "SELECT COUNT(DISTINCT json_extract(raw,'\$.shasum')) FROM v_events WHERE eventid LIKE 'cowrie.session.file_%' AND json_extract(raw,'\$.shasum') IS NOT NULL;" 2>/dev/null)
echo "  distinct content by hash          ${d:-?}"
echo "  ^ these two differ on purpose: redirection captures are named"
echo "    redir_<uuid>, so the file count exceeds the distinct content."
echo "    Never quote the file count as a number of samples."

# --- 4. the one figure that must be zero --------------------------------
echo
echo "--- the figure that must be zero ------------------------------"
z=$(sqlite3 decoy.sqlite "SELECT COUNT(*) FROM v_events WHERE eventid LIKE 'cowrie.session.file_%' AND json_extract(raw,'\$.url') IS NOT NULL AND ts > '2026-09-29T12:00:00';" 2>/dev/null)
if [ "${z:-1}" = "0" ]; then
  echo "  outbound fetches since the block   0   (correct)"
else
  echo "  outbound fetches since the block   $z   *** THE BLOCK IS NOT HOLDING ***"
  echo "  Stop. Do not publish any figure until this is explained."
fi

# --- 5. where each figure lives -----------------------------------------
cat <<'MAP'

--- which document carries which figure ------------------------------

  Update by transcription from above. Every one of these should also carry
  the AS-OF timestamp, and several carry a caveat that must survive the
  edit -- the caveat is the part that was missing when the figures were
  wrong.

  docs/first-contact.md
    - the first forty minutes: arrivals, credentials, the command list
    - the ATT&CK table, including the T1105 and T1497 corrections
    - CAVEAT TO KEEP: HISILICON was ACCEPTED 1,471 times. It is not
      evidence the imitation failed.

  docs/first-weekend.md
    - four-day totals: events, distinct sources, arrivals per door
    - the three proxy sources and the 443/2535 lead (still unexamined)
    - CAVEAT TO KEEP: three sources, not one.

  docs/rules-of-engagement.md
    - the outbound download problem: 81 fetches, 72 failures, 153
      connections, 8 hosts, distinct files
    - CAVEAT TO KEEP: why the first version said 259 and 331.

  docs/build.md
    - the firewall section's figures, and the file-count vs hash gap
    - the exclusion tally, which query 3 says to state alongside any figure
    - the OT decoy's verified reads

  the slide deck
    - hook, speed, passwords, origins slides
    - CAVEAT TO KEEP: origins are REGISTRATION, not location, and the
      percentages are of all arrivals so they will not sum to 100.

  ALWAYS, in every document:
    - lead with distinct sources, never events
    - quote arrivals (v_arrivals), never event counts, as "arrivals"
    - state the exclusion tally beside any total
    - the two doors opened eleven days apart: different denominators

MAP

echo "  figures as at $AS_OF"
echo
