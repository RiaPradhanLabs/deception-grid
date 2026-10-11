#!/usr/bin/env python3
"""
communities.py -- ML option 5, first pass: source-credential graph communities,
cross-checked against option 2's common-core clusters.

    python3 communities.py --db decoy-2026-10-09T0918Z.sqlite --seeds 10
    python3 communities.py --db ... --seeds 10 --csv communities-<stamp>.csv

Runs anywhere the snapshot is (the laptop included): standard library only,
read-only, prints no address, writes nothing unless --csv is given.

Why a second method. fingerprints.py (option 2) finds campaigns by a greedy
rule -- a source joins a cluster if it keeps a common core of credential pairs.
That rule has knobs (--core, --rel, --common) and an order; --shuffle measured
the order and the sensitivity run measured the knobs. What neither can measure
is whether a DIFFERENT method, given the same data, finds the same campaigns.
Two methods agreeing is a stronger claim than one method's self-checks. This
script is the second method. It is a first pass, not the analysis.

What it does:
  1. Same input as fingerprints.py: one set of (username, password) pairs per
     source from v_logins; sources below --min pairs are the denominator gap;
     pairs carried by more than --common of fingerprintable sources are glue
     and removed. Same defaults, so both methods see the same reduced sets.
  2. GRAPH: one node per source with a non-empty reduced set; an edge between
     two sources whose reduced sets have Jaccard >= --edge (default 0.3, the
     threshold overlap-test.py used on 6 October), weighted by that Jaccard.
     Sources with no edge are ISOLATES: counted, stated, left alone.
  3. COMMUNITIES: Louvain modularity optimisation (Blondel et al. 2008),
     implemented here with the standard library -- local moves until nothing
     improves, aggregate, repeat. Louvain depends on the node order, so
     --seeds N runs it N times in shuffled orders, keeps the partition with the
     highest modularity, and reports the Adjusted Rand Index of every other run
     against it -- the order-dependence, measured.
  4. AGREEMENT with option 2: the common-core rule of fingerprints.py (v5,
     9 October 2026 -- copied here, not imported, because that script runs on
     import; keep the two in step) is run on the same reduced sets, and the ARI
     between its labelling and the communities is printed, over the same
     sources. Then the cross-tab: for each large option-2 cluster, how many
     communities its members are spread over and the largest share; for each
     large community, which option-2 clusters it merges.
  5. The CHAIN question. overlap-test.py found a 41-source connected component
     at Jaccard 0.3 with no pair common to all of it. A connected component is
     not a campaign; a community might be. The output prints the component
     sizes and how the largest component is cut into communities, and for every
     large community its all-member core (which may be empty -- stated) beside
     the pairs carried by at least half its members.

What it prints: graph size, isolates, components; community count, sizes,
                modularity; the largest communities with core sizes and top
                pairs; agreement with option 2 (ARI, cross-tab); stability over
                seeds. Credential pairs are printed (they are the finding);
                addresses never are.
What it never does: print an address; write anything without --csv; connect to
                    anything.
"""
import argparse
import os
import random
import sqlite3
import sys
import time
from collections import Counter, defaultdict

ap = argparse.ArgumentParser()
ap.add_argument("--db", default="decoy.sqlite")
ap.add_argument("--min", type=int, default=5, help="distinct pairs needed to be fingerprintable (as fingerprints.py)")
ap.add_argument("--common", type=float, default=0.05, help="glue threshold, share of fingerprintable sources (as fingerprints.py)")
ap.add_argument("--edge", type=float, default=0.3, help="Jaccard at or above which two sources are joined by an edge")
ap.add_argument("--seeds", type=int, default=1, help="Louvain runs in shuffled node orders; best modularity kept")
ap.add_argument("--core", type=int, default=10, help="option-2 rule: pairs a cluster's core must keep")
ap.add_argument("--rel", type=float, default=0.5, help="option-2 rule: core >= this fraction of the median member's set")
ap.add_argument("--top", type=int, default=8, help="communities and clusters to describe")
ap.add_argument("--csv", metavar="PATH", help="one anonymised row per community (no address column); refuses to overwrite")
args = ap.parse_args()

if args.csv and os.path.exists(args.csv):
    sys.exit("refusing to overwrite %s -- choose another name" % args.csv)

t0 = time.time()
db = sqlite3.connect("file:%s?mode=ro" % args.db, uri=True)
rows = db.execute(
    "SELECT src_ip, username, password, substr(ts, 1, 10) FROM v_logins "
    "WHERE src_ip IS NOT NULL AND username IS NOT NULL").fetchall()
doors = dict(db.execute(
    "SELECT src_ip, GROUP_CONCAT(DISTINCT door) FROM v_arrivals "
    "WHERE src_ip IS NOT NULL GROUP BY src_ip").fetchall())
db.close()

sets = defaultdict(set)
days = defaultdict(set)
tries = Counter()
for ip, u, p, day in rows:
    sets[ip].add((u, p))
    days[ip].add(day)
    tries[(u, p)] += 1

all_sources = len(sets)
fp = {ip: s for ip, s in sets.items() if len(s) >= args.min}
carriers = Counter()
for s_ in fp.values():
    for pr in s_:
        carriers[pr] += 1
universal = {pr for pr, c in carriers.items() if c > args.common * len(fp)}
red = {ip: (s_ - universal) for ip, s_ in fp.items()}
nodes = sorted((ip for ip, s_ in red.items() if s_), key=lambda i: (-len(red[i]), i))
emptied = len(fp) - len(nodes)

print()
print("source-credential graph communities -- as at %s"
      % time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()))
print("  login rows that count          %d" % len(rows))
print("  sources with >=1 attempt       %d" % all_sources)
print("  fingerprintable (>=%d pairs)    %d   <- the denominator, as in fingerprints.py"
      % (args.min, len(fp)))
print("  glue pairs removed             %d   (carried by >%.0f%% of fingerprintable sources)"
      % (len(universal), 100 * args.common))
print("  nodes (non-empty after glue)   %d   (%d sources had only glue)" % (len(nodes), emptied))

# --- edges: Jaccard >= EDGE, via an inverted index on pairs ------------------
idx = {ip: k for k, ip in enumerate(nodes)}
size = [len(red[ip]) for ip in nodes]
by_pair = defaultdict(list)
for ip in nodes:
    k = idx[ip]
    for pr in red[ip]:
        by_pair[pr].append(k)
inter = Counter()
for members in by_pair.values():
    if len(members) < 2:
        continue
    members.sort()
    for a_i in range(len(members)):
        a = members[a_i]
        for b in members[a_i + 1:]:
            inter[(a, b)] += 1
adj = defaultdict(dict)
n_edges = 0
wsum = 0.0
for (a, b), c in inter.items():
    j = c / float(size[a] + size[b] - c)
    if j >= args.edge:
        adj[a][b] = j
        adj[b][a] = j
        n_edges += 1
        wsum += j
isolates = [k for k in range(len(nodes)) if k not in adj]

# connected components
comp = [-1] * len(nodes)
comp_sizes = []
for s in range(len(nodes)):
    if comp[s] != -1:
        continue
    cid = len(comp_sizes)
    stack = [s]
    comp[s] = cid
    n_ = 0
    while stack:
        v = stack.pop()
        n_ += 1
        for w in adj.get(v, ()):
            if comp[w] == -1:
                comp[w] = cid
                stack.append(w)
    comp_sizes.append(n_)
comp_multi = sorted((c for c in comp_sizes if c > 1), reverse=True)

print()
print("graph (edge = Jaccard >= %.2f on the reduced sets, weight = Jaccard)" % args.edge)
print("  edges                          %d   (mean weight %.2f)" % (n_edges, wsum / n_edges if n_edges else 0))
print("  isolates (no edge at all)      %d   (%.1f%% of nodes; stated, not clustered)"
      % (len(isolates), 100.0 * len(isolates) / max(1, len(nodes))))
print("  connected components (>=2)     %d   covering %d nodes; largest %d"
      % (len(comp_multi), sum(comp_multi), comp_multi[0] if comp_multi else 0))

# --- Louvain ------------------------------------------------------------------
def louvain(adj_, n, rnd):
    """Louvain on an undirected weighted graph. adj_[i][j] = weight (j != i).
    Returns a list: community label per original node."""
    # level-0 graph: every node its own community
    graph = {i: dict(adj_.get(i, {})) for i in range(n)}      # may hold self-loops at later levels
    membership = list(range(n))                                 # original node -> current super-node
    while True:
        node_ids = list(graph)
        k = {i: sum(graph[i].values()) for i in node_ids}       # weighted degree (self-loop counted once here)
        for i in node_ids:
            if i in graph[i]:
                k[i] += graph[i][i]                             # self-loop counts twice in the degree
        two_m = sum(k.values())
        if two_m == 0:
            break
        comm = {i: i for i in node_ids}
        tot = dict(k)                                           # sum of degrees per community
        improved_level = False
        moved = True
        sweeps = 0
        while moved and sweeps < 100:
            moved = False
            sweeps += 1
            order = list(node_ids)
            rnd.shuffle(order)
            for i in order:
                ci = comm[i]
                ki = k[i]
                # weights from i to each neighbouring community (self-loop excluded)
                w_to = defaultdict(float)
                for j, w in graph[i].items():
                    if j != i:
                        w_to[comm[j]] += w
                # remove i from its community
                tot[ci] -= ki
                best_c, best_gain = ci, w_to.get(ci, 0.0) - tot[ci] * ki / two_m
                for c, w in w_to.items():
                    gain = w - tot[c] * ki / two_m
                    if gain > best_gain + 1e-12:
                        best_c, best_gain = c, gain
                tot[best_c] += ki
                if best_c != ci:
                    comm[i] = best_c
                    moved = True
                    improved_level = True
        if not improved_level:
            break
        # aggregate
        relabel = {c: r for r, c in enumerate(sorted(set(comm.values())))}
        new_graph = defaultdict(lambda: defaultdict(float))
        for i in node_ids:
            ci = relabel[comm[i]]
            for j, w in graph[i].items():
                cj = relabel[comm[j]]
                if i == j:
                    new_graph[ci][ci] += w                      # existing self-loop, once
                elif ci == cj:
                    new_graph[ci][ci] += w / 2.0                # each internal edge seen from both ends
                else:
                    new_graph[ci][cj] += w
        graph = {c: dict(d) for c, d in new_graph.items()}
        for c in range(len(relabel)):
            graph.setdefault(c, {})
        membership = [relabel[comm[m]] for m in membership]
        if len(graph) == len(node_ids):
            break
    return membership

def modularity(labels):
    two_m = 2.0 * wsum
    if two_m == 0:
        return 0.0
    in_w = Counter()
    tot = Counter()
    for a in range(len(nodes)):
        tot[labels[a]] += sum(adj.get(a, {}).values())
        for b, w in adj.get(a, {}).items():
            if labels[a] == labels[b]:
                in_w[labels[a]] += w                            # both directions -> 2 x internal weight
    return sum(in_w[c] / two_m - (tot[c] / two_m) ** 2 for c in tot)

def ari(la, lb):
    """Adjusted Rand Index between two labelings over the same keys (as fingerprints.py)."""
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

runs = []
for seed in range(max(1, args.seeds)):
    lab = louvain(adj, len(nodes), random.Random(1000 + seed))
    runs.append((modularity(lab), seed, lab))
runs.sort(key=lambda r: -r[0])
best_q, best_seed, labels = runs[0]
best_lab = {nodes[k]: labels[k] for k in range(len(nodes))}

comms = defaultdict(list)
for k, c in enumerate(labels):
    comms[c].append(nodes[k])
multi_c = sorted((m for m in comms.values() if len(m) > 1), key=lambda m: -len(m))
in_multi = sum(len(m) for m in multi_c)

def dist(values):
    c = Counter()
    for v in values:
        k_ = ("2", "3-5", "6-10", "11-25", "26-100", ">100")[
            0 if v == 2 else 1 if v <= 5 else 2 if v <= 10 else 3 if v <= 25 else 4 if v <= 100 else 5]
        c[k_] += 1
    return "  ".join("%s:%d" % (k_, c[k_]) for k_ in ("2", "3-5", "6-10", "11-25", "26-100", ">100") if c[k_])

def median(v):
    v = sorted(v)
    return v[len(v) // 2] if v else 0

print()
print("communities (Louvain, best of %d order%s: seed %d, modularity %.3f)"
      % (len(runs), "" if len(runs) == 1 else "s", best_seed, best_q))
print("  communities with >=2 sources   %d   covering %d of %d nodes (%.1f%%; %.1f%% of fingerprintable)"
      % (len(multi_c), in_multi, len(nodes), 100.0 * in_multi / max(1, len(nodes)),
         100.0 * in_multi / max(1, len(fp))))
print("  community sizes                %s" % (dist(len(m) for m in multi_c) or "-"))
print("  largest community              %d sources" % (len(multi_c[0]) if multi_c else 0))
if comp_multi:
    big_comp = max(range(len(comp_sizes)), key=lambda c: comp_sizes[c])
    cut = Counter(labels[k] for k in range(len(nodes)) if comp[k] == big_comp)
    print("  largest component (%d) is cut  into %d communit%s: %s"
          % (comp_sizes[big_comp], len(cut), "y" if len(cut) == 1 else "ies",
             " ".join(str(v) for v in sorted(cut.values(), reverse=True)[:12])
             + (" ..." if len(cut) > 12 else "")))

# --- option-2 rule on the same reduced sets (fingerprints.py v5, copied) -----
def cluster_o2(order):
    out = []
    for ip in order:
        s_ = red[ip]
        if not s_:
            continue
        best, best_core = None, None
        for c in out:
            core = c["core"] & s_
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

o2 = cluster_o2(sorted(nodes, key=lambda i: -len(fp[i])))     # largest set first, as fingerprints.py
o2_lab = {}
for k, c in enumerate(o2):
    for ip in c["members"]:
        o2_lab[ip] = k
o2_multi = sorted((c for c in o2 if len(c["members"]) > 1), key=lambda c: -len(c["members"]))
o2_in = sum(len(c["members"]) for c in o2_multi)

def describe(members, title):
    allday = set().union(*(days[ip] for ip in members))
    dset = set()
    for ip in members:
        for d in (doors.get(ip) or "?").split(","):
            dset.add(d)
    core = set.intersection(*(red[ip] for ip in members))
    carry = Counter()
    for ip in members:
        carry.update(red[ip])
    half = [pr for pr, c in carry.items() if c >= 0.5 * len(members)]
    # mean internal edge weight
    ks = [idx[ip] for ip in members]
    ws = [adj[a][b] for a in ks for b in ks if b > a and b in adj.get(a, {})]
    top = sorted(half, key=lambda pr: (-carry[pr], -tries[pr]))[:5]
    print("  %-5s %-8d %-5d %-6d %-11d %-4.2f %-3d %s..%s  %-5s %s"
          % (title, len(members), len(core), len(half), median(len(red[ip]) for ip in members),
             sum(ws) / len(ws) if ws else 0.0,
             len(allday), min(allday)[5:], max(allday)[5:], "+".join(sorted(dset)),
             "  ".join("%s/%s(%d of %d)" % (u, p, carry[(u, p)], len(members)) for u, p in top)))
    return core, half

print()
print("the largest communities (core = pairs in EVERY member's set; half = pairs in at least half)")
print("  rank  sources  core  half   median_set  mean_J  days_span  doors  top pairs (members carrying)")
for r, m in enumerate(multi_c[:args.top], 1):
    core, half = describe(m, str(r))
    o2_parts = Counter(o2_lab[ip] for ip in m)
    named = []
    for c_id, n_ in o2_parts.most_common():
        if len(o2[c_id]["members"]) > 1:
            rank = next(i for i, c in enumerate(o2_multi, 1) if c is o2[c_id])
            named.append("o2 #%d (%d)" % (rank, n_))
    unclustered = sum(n_ for c_id, n_ in o2_parts.items() if len(o2[c_id]["members"]) == 1)
    print("        option 2 sees it as: %s%s"
          % (", ".join(named) if named else "no option-2 cluster",
             "" if not unclustered else "; %d source%s option 2 left unclustered"
             % (unclustered, "" if unclustered == 1 else "s")))
    if not core:
        print("        no pair common to all members -- a neighbourhood, not one list")

# --- agreement -------------------------------------------------------------------
print()
print("agreement with option 2 (common-core rule, core >= %d and >= %.0f%% of the median member; same reduced sets)"
      % (args.core, 100 * args.rel))
print("  option-2 clusters >=2 sources  %d   covering %d of %d nodes" % (len(o2_multi), o2_in, len(nodes)))
print("  communities >=2 sources        %d   covering %d of %d nodes" % (len(multi_c), in_multi, len(nodes)))
print("  adjusted Rand index            %.3f   over all %d nodes (singletons count as their own group)"
      % (ari(o2_lab, best_lab), len(nodes)))
both = [ip for ip in nodes if len(o2[o2_lab[ip]]["members"]) > 1 and len(comms[best_lab[ip]]) > 1]
if both:
    print("  ARI over sources BOTH methods  %.3f   over %d nodes"
          % (ari({ip: o2_lab[ip] for ip in both}, {ip: best_lab[ip] for ip in both}), len(both)))
print("  option-2 clusters -> communities:")
print("    o2 rank  sources  spread over  largest share in one community")
for r, c in enumerate(o2_multi[:args.top], 1):
    cnt = Counter(best_lab[ip] for ip in c["members"])
    print("    #%-7d %-8d %-12d %.0f%%" % (r, len(c["members"]), len(cnt),
                                           100.0 * max(cnt.values()) / len(c["members"])))
only_o2 = sum(1 for ip in nodes if len(o2[o2_lab[ip]]["members"]) > 1 and len(comms[best_lab[ip]]) == 1)
only_c = sum(1 for ip in nodes if len(o2[o2_lab[ip]]["members"]) == 1 and len(comms[best_lab[ip]]) > 1)
print("  clustered by option 2 only     %d   (in a cluster, but an isolate or singleton community)" % only_o2)
print("  clustered by communities only  %d   (in a community, but option 2 left them alone)" % only_c)

# --- stability over seeds --------------------------------------------------------
if len(runs) > 1:
    aris = sorted(ari(best_lab, {nodes[k]: r[2][k] for k in range(len(nodes))}) for r in runs[1:])
    qs = [r[0] for r in runs]
    print()
    print("order-dependence (%d shuffled orders vs the best)" % len(runs))
    print("  modularity                     min %.3f  max %.3f" % (min(qs), max(qs)))
    print("  adjusted Rand index            min %.3f  median %.3f  max %.3f"
          % (aris[0], aris[len(aris) // 2], aris[-1]))
    together = []
    for r, m in enumerate(multi_c[:args.top], 1):
        shares = []
        for _, _, lab in runs[1:]:
            cnt = Counter(lab[idx[ip]] for ip in m)
            shares.append(max(cnt.values()) / float(len(m)))
        shares.sort()
        together.append("#%d:%.0f%%" % (r, 100 * shares[len(shares) // 2]))
    print("  largest communities intact     %s" % "  ".join(together))

# --- csv -------------------------------------------------------------------------
if args.csv:
    import csv
    with open(args.csv, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["community_id", "sources", "core_pairs", "half_pairs", "median_set", "mean_jaccard",
                    "first_day", "last_day", "days_span", "doors", "o2_clusters_spanned",
                    "o2_largest_share", "o2_unclustered", "top_pairs"])
        for r, m in enumerate(multi_c, 1):
            allday = set().union(*(days[ip] for ip in m))
            dset = set()
            for ip in m:
                for d in (doors.get(ip) or "?").split(","):
                    dset.add(d)
            core = set.intersection(*(red[ip] for ip in m))
            carry = Counter()
            for ip in m:
                carry.update(red[ip])
            half = [pr for pr, c in carry.items() if c >= 0.5 * len(m)]
            ks = [idx[ip] for ip in m]
            ws = [adj[a][b] for a in ks for b in ks if b > a and b in adj.get(a, {})]
            parts = Counter(o2_lab[ip] for ip in m)
            multi_parts = {c_id: n_ for c_id, n_ in parts.items() if len(o2[c_id]["members"]) > 1}
            top = sorted(half, key=lambda pr: (-carry[pr], -tries[pr]))[:5]
            w.writerow([r, len(m), len(core), len(half), median(len(red[ip]) for ip in m),
                        round(sum(ws) / len(ws), 3) if ws else 0,
                        min(allday), max(allday), len(allday), "+".join(sorted(dset)),
                        len(multi_parts), round(max(multi_parts.values()) / float(len(m)), 3) if multi_parts else 0,
                        sum(n_ for c_id, n_ in parts.items() if len(o2[c_id]["members"]) == 1),
                        " ".join("%s/%s" % (u, p) for u, p in top)])
    print()
    print("  wrote %s: %d community rows, no address column (check: grep -E for a dotted quad)"
          % (args.csv, len(multi_c)))

print()
print("  %.1f s.  Louvain is order-dependent and modularity has a resolution limit:" % (time.time() - t0))
print("  small campaigns inside a dense neighbourhood can be merged, and a chain can be")
print("  cut anywhere -- --seeds N measures the first; the core/half columns show the")
print("  second.  Nothing here is an address.")
