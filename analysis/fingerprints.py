#!/usr/bin/env python3
"""
fingerprints.py -- ML option 2, first pass: credential sets as campaign fingerprints.

    cd ~/analysis && python3 fingerprints.py            # read-only, prints aggregates
    cd ~/analysis && python3 fingerprints.py --db other.sqlite --core 10 --min 5

overlap-test.py (6 October 2026) measured the premise: sources on this sensor
share credential dictionaries for a minority, inside a majority that share
little, and single-linkage at Jaccard 0.3 produced a 41-source chain with NO
credential common to all of it -- a chain, not a dictionary. So option 2 was
re-scoped: cluster on a COMMON CORE and state the denominator. This script is
that rule, implemented and measured. It is a first pass, not the analysis.

What it does:
  1. One set of (username, password) pairs per source, from v_logins (rows that
     count -- analyst, loopback and artefact rows are already excluded there).
     Sources with fewer than MIN_PAIRS distinct pairs are the DENOMINATOR GAP:
     counted, never clustered.
  2. TWINS: sources whose sets are identical, or within Jaccard >= TWIN of some
     other source. Reported as a count, because identical lists are the
     strongest evidence of one tool or one list being reused.
  3. COMMON-CORE clusters: sources are visited largest-set first; each joins the
     existing cluster whose running INTERSECTION with its set stays at least
     CORE pairs (choosing the cluster that keeps the largest core), else starts
     a new one. A cluster's core can only shrink as it grows, so a chain of
     pairwise-similar sources that share nothing overall cannot form. Greedy
     and order-dependent -- stated, not hidden; a later pass can refine it.
  The first real run (9 October 2026, 10:59 UTC) showed the absolute core
  letting UNIVERSAL credentials -- root/12345, root/root, admin/admin, the
  pairs every wordlist carries -- glue 25 unrelated dictionaries of ~1,100
  pairs into one "campaign" sharing 14. So, second version, same day:
  4. UNIVERSAL pairs -- tried by more than COMMON of the fingerprintable
     sources -- are removed from every set before clustering and listed. They
     are evidence of nothing except that the list exists.
     Limitation, stated in the output: a list shared by more than COMMON of
     all fingerprintable sources would itself be discarded as universal. The
     output prints the largest identical-set group beside the threshold so the
     reader can see whether that is happening.
  5. The core must be at least CORE pairs AND at least REL of the MEDIAN
     member's (reduced) set, the candidate included: a core of 14 against sets
     of 1,100 no longer qualifies; 146 against 170 does. (The second run, 14:24
     UTC, used the SMALLEST member instead, and one 20-pair list anchored
     twenty 1,100-pair dictionaries that happened to contain it. Median fixes
     that; a 5 % common-pair threshold replaces the 20 % one, which removed
     nothing because no pair here is carried by a fifth of the sources.)
  6. --shuffle N re-runs the clustering in N random source orders and reports
     the Adjusted Rand Index of each against the largest-first run, plus how
     often the members of the largest clusters stay together -- the
     order-dependence, measured rather than disclaimed.
  7. --clients joins each cluster to the SSH client strings and HASSH
     fingerprints its members announced (the twelve clients of
     docs/who-gets-in.md): a campaign that is one tool shows as one string.
     --success counts, per cluster, the sources that got in and their logins.
What it prints: denominators; glue pairs; twin counts; cluster count and
                size distribution;
                for the largest clusters, size, core size, median set size, day
                span, doors, and the five most-tried pairs IN THE CORE.
                Credential pairs are printed (they are the finding); addresses
                never are.
What it never does: print an address, or write anything.
"""
import argparse
import sqlite3
import sys
import time
from collections import Counter, defaultdict

ap = argparse.ArgumentParser()
ap.add_argument("--db", default="decoy.sqlite")
ap.add_argument("--min", type=int, default=5, help="distinct pairs needed to be fingerprintable")
ap.add_argument("--core", type=int, default=10, help="pairs a cluster's shared core must keep")
ap.add_argument("--twin", type=float, default=0.9, help="Jaccard at or above which two sources are twins")
ap.add_argument("--rel", type=float, default=0.5, help="core must also be >= this fraction of the smallest member's set")
ap.add_argument("--common", type=float, default=0.05, help="pairs tried by more than this fraction of fingerprintable sources are common glue and ignored")
ap.add_argument("--shuffle", type=int, default=0, help="re-run the clustering in N random orders and report stability")
ap.add_argument("--legacy", action="store_true", help="first-version rule: absolute core only, universal pairs kept")
ap.add_argument("--clients", action="store_true", help="per cluster: dominant SSH client string, its share, distinct HASSH, door mix")
ap.add_argument("--success", action="store_true", help="per cluster: sources that got in and successful logins")
ap.add_argument("--top", type=int, default=8, help="clusters to describe")
args = ap.parse_args()

t0 = time.time()
db = sqlite3.connect("file:%s?mode=ro" % args.db, uri=True)
rows = db.execute(
    "SELECT src_ip, username, password, substr(ts, 1, 10), ok FROM v_logins "
    "WHERE src_ip IS NOT NULL AND username IS NOT NULL").fetchall()
doors = dict(db.execute(
    "SELECT src_ip, GROUP_CONCAT(DISTINCT door) FROM v_arrivals "
    "WHERE src_ip IS NOT NULL GROUP BY src_ip").fetchall())
cli_ver, cli_hassh = defaultdict(Counter), defaultdict(Counter)
if args.clients:
    for ip, v in db.execute(
            "SELECT src_ip, json_extract(raw, '$.version') FROM events "
            "WHERE excluded IS NULL AND eventid = 'cowrie.client.version' AND src_ip IS NOT NULL"):
        cli_ver[ip][v or "?"] += 1
    for ip, h in db.execute(
            "SELECT src_ip, json_extract(raw, '$.hassh') FROM events "
            "WHERE excluded IS NULL AND eventid = 'cowrie.client.kex' AND src_ip IS NOT NULL"):
        cli_hassh[ip][h or "?"] += 1
db.close()

sets = defaultdict(set)
days = defaultdict(set)
tries = Counter()
succ = Counter()
for ip, u, p, day, ok in rows:
    sets[ip].add((u, p))
    days[ip].add(day)
    tries[(u, p)] += 1
    if ok:
        succ[ip] += 1

all_sources = len(sets)
fp = {ip: s for ip, s in sets.items() if len(s) >= args.min}
gap = all_sources - len(fp)

print()
print("credential-set fingerprints -- as at %s"
      % time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()))
print("  login rows that count          %d" % len(rows))
print("  sources with >=1 attempt       %d" % all_sources)
print("  fingerprintable (>=%d pairs)    %d   <- the denominator for everything below"
      % (args.min, len(fp)))
print("  too few pairs to say           %d   (%.1f%% of sources; stated, not clustered)"
      % (gap, 100.0 * gap / max(1, all_sources)))

# --- universal pairs --------------------------------------------------------
carriers = Counter()
for s_ in fp.values():
    for pr in s_:
        carriers[pr] += 1
universal = {pr for pr, c in carriers.items() if c > args.common * len(fp)}
if args.legacy:
    universal = set()
red = {ip: (s_ - universal) for ip, s_ in fp.items()}
emptied = sum(1 for s_ in red.values() if len(s_) == 0)
print()
print("common glue pairs (tried by >%.0f%% of fingerprintable sources; ignored for clustering)"
      % (100 * args.common))
print("  count                          %d" % len(universal))
if universal:
    top_u = sorted(universal, key=lambda pr: -carriers[pr])[:8]
    print("  most widely carried            %s"
          % "  ".join("%s/%s(%d src)" % (u, p, carriers[(u, p)]) for u, p in top_u))
    print("  sources left with no pairs     %d   (their whole list was glue)" % emptied)
print("  self-check: a list shared by more than %d sources would itself count as glue;"
      % int(args.common * len(fp)))

# --- twins ------------------------------------------------------------------
frozen = {ip: frozenset(s) for ip, s in fp.items()}
by_set = defaultdict(list)
for ip, s in frozen.items():
    by_set[s].append(ip)
identical_groups = [v for v in by_set.values() if len(v) > 1]
identical_sources = sum(len(v) for v in identical_groups)

ips = sorted(fp, key=lambda i: -len(fp[i]))
has_twin = set()
n = len(ips)
# pairwise Jaccard only among sources whose sizes could reach the twin threshold
for i in range(n):
    a = fp[ips[i]]
    la = len(a)
    for j in range(i + 1, n):
        b = fp[ips[j]]
        lb = len(b)
        if lb < args.twin * la:          # sizes too different to be twins
            break
        inter = len(a & b)
        if inter / (la + lb - inter) >= args.twin:
            has_twin.add(ips[i]); has_twin.add(ips[j])

print()
print("twins")
print("  identical credential sets      %d sources in %d groups (largest group %d)"
      % (identical_sources, len(identical_groups),
         max((len(v) for v in identical_groups), default=0)))
print("  near-identical (Jaccard>=%.1f)  %d sources   (%.1f%% of fingerprintable)"
      % (args.twin, len(has_twin), 100.0 * len(has_twin) / max(1, len(fp))))
print("  self-check continued: the largest identical-set group is %d sources, so %s"
      % (max((len(v) for v in identical_groups), default=0),
         "no observed list is at risk of being discarded as glue"
         if max((len(v) for v in identical_groups), default=0) <= args.common * len(fp)
         else "RAISE --common: a real shared list is being discarded as glue"))

# --- common-core clusters ---------------------------------------------------
def cluster(order):
    """Greedy common-core clustering over `order` (a list of source ids)."""
    out = []
    for ip in order:
        s_ = red[ip]
        if not s_:
            continue
        best, best_core = None, None
        for c in out:
            core = c["core"] & s_
            if args.legacy:
                need = args.core
            else:
                # relative to the MEDIAN member size with the candidate included:
                # one small list cannot anchor a cluster of big dictionaries, and
                # one big dictionary cannot be glued onto a cluster of small lists.
                sizes_ = sorted(c["sizes"] + [len(s_)])
                need = max(args.core, args.rel * sizes_[len(sizes_) // 2])
            if len(core) >= need and (best_core is None or len(core) > len(best_core)):
                best, best_core = c, core
        if best is None:
            out.append({"core": set(s_), "members": [ip], "sizes": [len(s_)]})
        else:
            best["core"] = best_core
            best["members"].append(ip)
            best["sizes"].append(len(s_))
    return out

clusters = cluster(ips)   # largest set first
multi = [c for c in clusters if len(c["members"]) > 1]
single = len(clusters) - len(multi)
in_multi = sum(len(c["members"]) for c in multi)
sizes = sorted((len(c["members"]) for c in multi), reverse=True)

def dist(values):
    c = Counter()
    for v in values:
        k = ("2", "3-5", "6-10", "11-25", "26-100", ">100")[
            0 if v == 2 else 1 if v <= 5 else 2 if v <= 10 else 3 if v <= 25 else 4 if v <= 100 else 5]
        c[k] += 1
    return "  ".join("%s:%d" % (k, c[k]) for k in ("2", "3-5", "6-10", "11-25", "26-100", ">100") if c[k])

print()
print("common-core clusters (core >= %d pairs%s, kept as the cluster grows)"
      % (args.core, "" if args.legacy else " and >= %.0f%% of the median member's set" % (100 * args.rel)))
print("  clusters with >=2 sources      %d   covering %d of %d fingerprintable sources (%.1f%%)"
      % (len(multi), in_multi, len(fp), 100.0 * in_multi / max(1, len(fp))))
print("  sources in no cluster          %d   (fingerprintable, but share <%d pairs with any cluster)"
      % (single, args.core))
print("  cluster sizes                  %s" % (dist(sizes) or "-"))
print("  largest cluster                %d sources" % (sizes[0] if sizes else 0))

def median(v):
    v = sorted(v)
    return v[len(v) // 2] if v else 0

print()
print("the largest clusters")
print("  rank  sources  core  median_set  days_span  doors  top pairs in the core (tries across the collection)")
multi.sort(key=lambda c: -len(c["members"]))
for r, c in enumerate(multi[:args.top], 1):
    m = c["members"]
    allday = set().union(*(days[ip] for ip in m))
    span = (len(allday), min(allday), max(allday))
    dset = set()
    for ip in m:
        for d in (doors.get(ip) or "?").split(","):
            dset.add(d)
    top = sorted(c["core"], key=lambda p: -tries[p])[:5]
    print("  %-5d %-8d %-5d %-11d %-3d %s..%s  %-5s %s"
          % (r, len(m), len(c["core"]), median(len(fp[ip]) for ip in m),
             span[0], span[1][5:], span[2][5:], "+".join(sorted(dset)),
             "  ".join("%s/%s(%d)" % (u, p, tries[(u, p)]) for u, p in top)))
    extra = []
    if args.clients:
        vers = Counter()
        hs = set()
        telnet_only = 0
        for ip in m:
            if cli_ver.get(ip):
                vers[cli_ver[ip].most_common(1)[0][0]] += 1
                hs.update(cli_hassh.get(ip, {}).keys())
            else:
                telnet_only += 1
        if vers:
            dom, dn = vers.most_common(1)[0]
            extra.append("clients: %d of %d on %s%s; %d distinct string%s, %d HASSH%s"
                         % (dn, len(m), dom,
                            "" if telnet_only == 0 else " (%d telnet-only)" % telnet_only,
                            len(vers), "" if len(vers) == 1 else "s",
                            len(hs), "" if len(hs) == 1 else "es"))
        else:
            extra.append("clients: telnet only (%d), no SSH client string" % len(m))
    if args.success:
        got_in = sum(1 for ip in m if succ.get(ip))
        extra.append("got in: %d of %d sources, %d successful logins" % (got_in, len(m), sum(succ.get(ip, 0) for ip in m)))
    for e in extra:
        print("        %s" % e)
    if args.clients and len(m) >= 3:
        vers_ = Counter(cli_ver[ip].most_common(1)[0][0] for ip in m if cli_ver.get(ip))
        c["single_client"] = bool(vers_) and vers_.most_common(1)[0][1] >= 0.9 * len(m)

if args.clients:
    big3 = [c for c in multi if len(c["members"]) >= 3]
    # evaluate single-client for every cluster of >= 3, not only the printed ones
    sc = 0
    for c in big3:
        vers_ = Counter(cli_ver[ip].most_common(1)[0][0] for ip in c["members"] if cli_ver.get(ip))
        if vers_ and vers_.most_common(1)[0][1] >= 0.9 * len(c["members"]):
            sc += 1
    print()
    print("clusters x clients")
    print("  clusters with >=3 sources      %d   of which single-client (>=90%% one SSH string) %d" % (len(big3), sc))
    print("  (a campaign that is one tool shows as one client string; a shared list run by")
    print("   many tools shows as several -- the join between options 2 and 4)")
if args.success:
    print()
    print("clusters x success")
    tot_in = sum(1 for c in multi for ip in c["members"] if succ.get(ip))
    tot_src = sum(len(c["members"]) for c in multi)
    print("  clustered sources that got in  %d of %d" % (tot_in, tot_src))
    print("  unclustered that got in        %d of %d"
          % (sum(1 for c in clusters if len(c["members"]) == 1 and succ.get(c["members"][0])), single))

# --- order-independence -----------------------------------------------------
def labels_of(cl):
    lab = {}
    for k, c in enumerate(cl):
        for ip in c["members"]:
            lab[ip] = k
    return lab

def ari(la, lb):
    """Adjusted Rand Index between two labelings over the same keys."""
    keys = [k for k in la if k in lb]
    cont = Counter((la[k], lb[k]) for k in keys)
    ra = Counter(la[k] for k in keys)
    cb = Counter(lb[k] for k in keys)
    c2 = lambda x: x * (x - 1) / 2.0
    sum_ij = sum(c2(v) for v in cont.values())
    sum_a = sum(c2(v) for v in ra.values())
    sum_b = sum(c2(v) for v in cb.values())
    n2 = c2(len(keys))
    if n2 == 0:
        return 1.0
    expected = sum_a * sum_b / n2
    maxi = (sum_a + sum_b) / 2.0
    return 1.0 if maxi == expected else (sum_ij - expected) / (maxi - expected)

if args.shuffle:
    import random
    base = labels_of(clusters)
    aris, together = [], defaultdict(list)
    big = [c["members"] for c in multi[:args.top]]
    for seed in range(args.shuffle):
        rnd = random.Random(1000 + seed)
        order = list(ips)
        rnd.shuffle(order)
        alt = cluster(order)
        lab = labels_of(alt)
        aris.append(ari(base, lab))
        for r, members in enumerate(big, 1):
            # share of this cluster's members that land in one alt cluster
            cnt = Counter(lab.get(ip, -1) for ip in members)
            together[r].append(max(cnt.values()) / float(len(members)))
    aris.sort()
    print()
    print("order-independence (%d shuffled orders vs largest-first)" % args.shuffle)
    print("  adjusted Rand index            min %.3f  median %.3f  max %.3f"
          % (aris[0], aris[len(aris) // 2], aris[-1]))
    print("  largest clusters kept intact   %s"
          % "  ".join("#%d:%.0f%%" % (r, 100 * sum(v) / len(v)) for r, v in sorted(together.items())))
    print("  (1.000 = identical clusters in every order; 'intact' = median share of a cluster's")
    print("   members that stay together under reordering)")

print()
print("  %.1f s.  Greedy, largest-first, order-dependent: a source joins the first"
      % (time.time() - t0))
print("  cluster whose core it keeps; a different order can move a source between")
print("  two clusters it fits -- --shuffle N measures by how much.  Nothing here is an address.")
