#!/usr/bin/env bash
#
# geo-lookup.sh -- registration country for the busiest source addresses.
#
#   cd ~/analysis && ./geo-lookup.sh [how_many]     # default 50
#
# WHAT THIS CLAIMS, AND WHAT IT DOES NOT
#
# This reads the `country:` field from the regional internet registry's record
# for each address -- who was ALLOCATED the address block. That is a different
# claim from a geolocation database, which estimates where a machine physically
# sits. The deck slide says "registered in", so whois is the right instrument:
# it states exactly what the slide claims rather than something adjacent.
#
# Neither answers "which country attacked us". Renting a server costs a few
# euros a month from anywhere on earth, and roughly two thirds of our traffic is
# registered in the United States and France, which are hosting territories.
# Say so whenever this data is shown.
#
# OUTBOUND TRAFFIC
#
# whois queries the registries, NOT the addresses in the log. Nothing here
# connects to, scans, or probes anything that appeared in the honeypot data --
# see docs/rules-of-engagement.md. It runs as the analyst user; the cowrie user
# is firewalled out of all outbound connections.
#
# The results are cached in geo.sqlite, kept separate from decoy.sqlite so that
# rebuilding the ingest database cannot wipe work that took minutes of polite
# rate-limited querying. A re-run only looks up addresses it has not seen.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
DB="${DECOY_DB:-$HERE/decoy.sqlite}"
GEO="${DECOY_GEO:-$HERE/geo.sqlite}"
TOP="${1:-50}"
PAUSE="${PAUSE:-2}"        # seconds between queries; the registries throttle

command -v whois >/dev/null || { echo "whois not installed: sudo apt-get install -y whois"; exit 1; }
[ -r "$DB" ] || { echo "cannot read $DB -- run ingest.py first"; exit 1; }

sqlite3 "$GEO" 'CREATE TABLE IF NOT EXISTS geo (
  src_ip   TEXT PRIMARY KEY,
  cc       TEXT NOT NULL,
  looked_up TEXT NOT NULL
);'

# The busiest sources by ARRIVALS, not by events: one stubborn scanner produces
# tens of thousands of events and that is not the same as being widespread.
mapfile -t ips < <(sqlite3 "$DB" "
  SELECT src_ip FROM v_events
   WHERE eventid = 'cowrie.session.connect' AND src_ip IS NOT NULL
   GROUP BY 1 ORDER BY COUNT(*) DESC LIMIT $TOP;")

echo "${#ips[@]} addresses to consider, pausing ${PAUSE}s between lookups"

new=0 cached=0
for ip in "${ips[@]}"; do
  if [ -n "$(sqlite3 "$GEO" "SELECT 1 FROM geo WHERE src_ip = '$ip';")" ]; then
    cached=$((cached + 1))
    continue
  fi
  # `|| true` is load-bearing: with `set -o pipefail`, grep finding no country
  # line -- or head closing the pipe early on a long record -- makes the whole
  # pipeline non-zero, and `set -e` would abort the run on the first address
  # whose record does not parse. An UNKNOWN is a result, not a failure.
  cc="$(timeout 10 whois "$ip" 2>/dev/null \
        | grep -iE '^(country|country-code):' | head -1 | awk '{print toupper($NF)}' || true)"
  # A two-letter code or nothing. Anything else means the record was unparseable
  # and UNKNOWN is the honest answer -- never a guess.
  case "$cc" in
    [A-Z][A-Z]) : ;;
    *) cc="UNKNOWN" ;;
  esac
  sqlite3 "$GEO" "INSERT OR REPLACE INTO geo (src_ip, cc, looked_up)
                  VALUES ('$ip', '$cc', datetime('now'));"
  new=$((new + 1))
  printf '  %-16s %s\n' "$ip" "$cc"
  sleep "$PAUSE"
done

echo "looked up $new, already cached $cached"
echo

# Coverage first, because a country table without it invites overreading.
sqlite3 -header -column "$DB" "
ATTACH '$GEO' AS g;
SELECT (SELECT COUNT(*) FROM v_events e JOIN g.geo ON g.geo.src_ip = e.src_ip
          WHERE e.eventid = 'cowrie.session.connect')              AS arrivals_covered,
       (SELECT COUNT(*) FROM v_events
          WHERE eventid = 'cowrie.session.connect')                AS arrivals_total,
       (SELECT COUNT(*) FROM g.geo)                                AS sources_looked_up,
       (SELECT COUNT(DISTINCT src_ip) FROM v_events
          WHERE eventid = 'cowrie.session.connect')                AS sources_total;"

echo
sqlite3 -header -column "$DB" "
ATTACH '$GEO' AS g;
SELECT g.geo.cc                  AS country,
       COUNT(*)                  AS arrivals,
       COUNT(DISTINCT e.src_ip)  AS sources,
       ROUND(100.0 * COUNT(*) /
             (SELECT COUNT(*) FROM v_events
               WHERE eventid = 'cowrie.session.connect'), 1) AS pct_of_all_arrivals
  FROM v_events e
  JOIN g.geo ON g.geo.src_ip = e.src_ip
 WHERE e.eventid = 'cowrie.session.connect'
 GROUP BY 1
 ORDER BY 2 DESC;"

echo
echo "Percentages are of ALL arrivals, so they do not sum to 100: the sources"
echo "not looked up are the remainder. Countries named here are complete only"
echo "within the $TOP most persistent sources."
