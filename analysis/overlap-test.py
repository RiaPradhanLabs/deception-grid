#!/usr/bin/env python3
"""
overlap-test.py -- does this dataset contain shared credential dictionaries?

    cd ~/analysis && python3 overlap-test.py            # read-only, prints aggregates

The premise under ML spin-off options 2 and 5 is that sources share credential
lists, so the SET of (username, password) pairs a source tries fingerprints a
campaign. Nobody had measured whether that is true of this sensor's data before
committing ~50 hours to it. This script measures it and nothing else.

What it does:   reads v_logins (rows that count -- analyst, loopback and artefact
                rows already excluded), builds one set of credential pairs per
                source, and compares every pair of sources that tried at least
                MIN_PAIRS distinct credentials, by Jaccard similarity
                |A & B| / |A | B|.
What it prints: how many sources qualify, how similar each is to its nearest
                neighbour, how many source pairs exceed 0.3 / 0.5 / 0.9, and the
                connected components at 0.3 (the "dictionaries"). Aggregates only.
What it never does: print an address, a credential, or write anything.
"""
import itertools
import sqlite3
import sys
import time

DB = "decoy.sqlite"
MIN_PAIRS = 5          # a source with fewer distinct pairs cannot be fingerprinted
THRESHOLDS = (0.3, 0.5, 0.9)
MAX_COMBOS = 2_000_000 # safety cap; above this the busiest sources are kept

t0 = time.time()
db = sqlite3.connect("file:%s?mode=ro" % DB, uri=True)
rows = db.execute(
    "SELECT src_ip, username, password FROM v_logins "
    "WHERE src_ip IS NOT NULL AND username IS NOT NULL").fetchall()
db.close()

by_src = {}
for ip, u, p in rows:
    by_src.setdefault(ip, set()).add((u, p))

all_sources = len(by_src)
pairs_total = len({(u, p) for u, p in ((r[1], r[2]) for r in rows)})
sizes = sorted(len(v) for v in by_src.values())

def pct(values, q):
    if not values:
        return 0
    return values[min(len(values) - 1, int(q * (len(values) - 1)))]

print()
print("credential overlap test -- as at %s" % time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()))
print("  login rows that count       %d" % len(rows))
print("  sources with >=1 attempt    %d" % all_sources)
print("  distinct credential pairs   %d" % pairs_total)
print("  pairs per source            median %d, p90 %d, max %d"
      % (pct(sizes, 0.5), pct(sizes, 0.9), sizes[-1] if sizes else 0))

qual = {ip: s for ip, s in by_src.items() if len(s) >= MIN_PAIRS}
dropped = all_sources - len(qual)
print("  sources with >=%d pairs      %d   (%d too small to fingerprint, dropped)"
      % (MIN_PAIRS, len(qual), dropped))

ips = sorted(qual, key=lambda k: -len(qual[k]))
n = len(ips)
combos = n * (n - 1) // 2
if combos > MAX_COMBOS:
    # keep the busiest sources so the cap is honest and stated
    keep = int((2 * MAX_COMBOS) ** 0.5)
    print("  %d source pairs exceeds the cap of %d; keeping the %d busiest sources"
          % (combos, MAX_COMBOS, keep))
    ips = ips[:keep]
    n = len(ips)
    combos = n * (n - 1) // 2
print("  source pairs compared       %d" % combos)

sets = [qual[ip] for ip in ips]
best = [0.0] * n
over = {t: 0 for t in THRESHOLDS}
edges = []   # at the lowest threshold, for components
for i, j in itertools.combinations(range(n), 2):
    a, b = sets[i], sets[j]
    inter = len(a & b)
    if inter == 0:
        continue
    jac = inter / float(len(a) + len(b) - inter)
    if jac > best[i]:
        best[i] = jac
    if jac > best[j]:
        best[j] = jac
    for t in THRESHOLDS:
        if jac >= t:
            over[t] += 1
    if jac >= THRESHOLDS[0]:
        edges.append((i, j))

bs = sorted(best)
print()
print("nearest-neighbour similarity, per source (Jaccard to its closest other source)")
print("  median %.2f   p75 %.2f   p90 %.2f   max %.2f" % (pct(bs, .5), pct(bs, .75), pct(bs, .9), bs[-1] if bs else 0))
print("  sources whose nearest neighbour is  0.0  (share nothing with anyone)  %d  (%.0f%%)"
      % (sum(1 for b in bs if b == 0), 100.0 * sum(1 for b in bs if b == 0) / max(n, 1)))
print("  sources with a neighbour >= 0.3                                      %d  (%.0f%%)"
      % (sum(1 for b in bs if b >= 0.3), 100.0 * sum(1 for b in bs if b >= 0.3) / max(n, 1)))
print("  sources with a neighbour >= 0.9  (near-identical dictionary)         %d  (%.0f%%)"
      % (sum(1 for b in bs if b >= 0.9), 100.0 * sum(1 for b in bs if b >= 0.9) / max(n, 1)))
print()
print("source pairs above each threshold")
for t in THRESHOLDS:
    print("  Jaccard >= %.1f   %d" % (t, over[t]))

# connected components at the lowest threshold = candidate dictionaries
parent = list(range(n))
def find(x):
    while parent[x] != x:
        parent[x] = parent[parent[x]]
        x = parent[x]
    return x
for i, j in edges:
    ri, rj = find(i), find(j)
    if ri != rj:
        parent[ri] = rj
comp = {}
for i in range(n):
    comp.setdefault(find(i), []).append(i)
groups = sorted((v for v in comp.values() if len(v) > 1), key=len, reverse=True)
print()
print("connected components at Jaccard >= %.1f  (candidate shared dictionaries)" % THRESHOLDS[0])
print("  components of 2+ sources    %d" % len(groups))
print("  sources inside a component  %d of %d" % (sum(len(g) for g in groups), n))
print("  largest components (sources, and credential pairs common to ALL members):")
for g in groups[:8]:
    common = set.intersection(*(sets[i] for i in g))
    print("    %4d sources   %4d pairs common to all" % (len(g), len(common)))
print()
print("reading guide")
print("  Most sources with a neighbour >= 0.3 and a handful of large components with")
print("  many pairs common to all members  -> dictionaries are shared; options 2 and 5 stand.")
print("  Most sources at 0.0 and components that are small or share only a pair or two")
print("  -> the premise does not hold here; re-scope before spending the hours.")
print()
print("  read-only; nothing written; no address or credential printed.  %.1f s" % (time.time() - t0))
