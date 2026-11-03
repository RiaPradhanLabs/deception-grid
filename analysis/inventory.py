#!/usr/bin/env python3
"""Inventory tables for the captured files -- from the feature CSV, not the files.

Reads analysis/file-features.csv (written by features-files.py) and prints the
tables the inventory note needs: files and distinct contents by kind, ELF
architectures counted as distinct contents, non-ELF contents by file(1) class,
a size distribution, entropy bands, the most-copied contents, and which
contents arrived both as hash-named files and as shell-redirect captures.

Two optional joins, both read-only:

  --dir   stat() the captured files for their modification times (no file is
          opened) and print first/last capture per kind and arrivals per ISO
          week, with the number of contents seen for the first time that week.
  --db    the four kinds of file event from decoy.sqlite (query 13's rule,
          copied verbatim: eventid AND url decide, never url alone), the
          hash-named files the database knows and does not know, and the
          fetched / pushed / blocked activity per week as COUNTS.

Nothing here prints an address or a URL. Sources and destinations appear only
as counts. Content hashes are printed as a 12-character prefix, which is
enough to find the row in the CSV and useless to anyone else.

Standard library only. Installs nothing, executes nothing, opens no socket,
opens no captured file. The CSV is the input; the files are stat()ed at most.

    python3 inventory.py --csv file-features.csv
    sudo python3 inventory.py --csv file-features.csv --dir /home/cowrie/cowrie/var/lib/cowrie/downloads --db decoy.sqlite

The distinct-sha256 count is the sample count. The file count never is.
"""

import argparse
import csv
import datetime as dt
import os
import sqlite3
import statistics
import sys
from collections import Counter, defaultdict

csv.field_size_limit(1 << 26)

SIZE_BUCKETS = [
    ("1 byte", lambda s: s == 1),
    ("2 B - 1 KiB", lambda s: 1 < s < 1024),
    ("1 KiB - 64 KiB", lambda s: 1024 <= s < 64 * 1024),
    ("64 KiB - 1 MiB", lambda s: 64 * 1024 <= s < 1024 * 1024),
    ("1 MiB - 16 MiB", lambda s: 1024 * 1024 <= s < 16 * 1024 * 1024),
    ("16 MiB and above", lambda s: s >= 16 * 1024 * 1024),
]

ENTROPY_BANDS = [
    ("< 1.0  (near-constant)", 0.0, 1.0),
    ("1.0 - 5.0", 1.0, 5.0),
    ("5.0 - 6.5  (typical code)", 5.0, 6.5),
    ("6.5 - 7.5", 6.5, 7.5),
    (">= 7.5  (compressed or packed)", 7.5, 9.0),
]


def human(n):
    n = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or unit == "GiB":
            return "%.1f %s" % (n, unit) if unit != "B" else "%d B" % n
        n /= 1024.0


def magic_class(magic):
    """A short, stable label for a file(1) description."""
    m = (magic or "").strip()
    low = m.lower()
    if low.startswith("elf"):
        return "ELF"
    if "shell script" in low or "/bin/sh" in low or "bash" in low:
        return "shell script"
    if low.startswith("very short file"):
        return "very short file"
    if low == "empty":
        return "empty"
    if "text" in low:
        return "text"
    if low.startswith("data"):
        return "data (unrecognised)"
    if "gzip" in low or "compressed" in low or "archive" in low or "zip" in low:
        return "archive / compressed"
    return m.split(",")[0][:40] or "(no magic)"


def load(csv_path):
    rows = []
    with open(csv_path, newline="") as fh:
        for r in csv.DictReader(fh):
            r["size"] = int(r["size"])
            r["features_bytes"] = int(r["features_bytes"] or 0)
            r["elf"] = int(r["elf"] or 0)
            try:
                r["ent_total"] = float(r["ent_total"])
            except (TypeError, ValueError):
                r["ent_total"] = None
            rows.append(r)
    return rows


def contents(rows):
    """One record per distinct sha256, with the kinds and copies behind it."""
    by = {}
    for r in rows:
        c = by.get(r["sha256"])
        if c is None:
            c = by[r["sha256"]] = {"row": r, "copies": 0, "kinds": Counter()}
        c["copies"] += 1
        c["kinds"][r["kind"]] += 1
    return by


def table(headers, lines, widths=None):
    widths = widths or [max(len(str(h)), *(len(str(l[i])) for l in lines)) if lines else len(str(h))
                        for i, h in enumerate(headers)]
    fmt = "  " + "  ".join("%%-%ds" % w for w in widths)
    print(fmt % tuple(headers))
    print(fmt % tuple("-" * w for w in widths))
    for l in lines:
        print(fmt % tuple(str(x) for x in l))


def section(title):
    print()
    print("=== %s ===" % title)


# ---------------------------------------------------------------- CSV tables

def report_csv(rows, by):
    kinds = sorted({r["kind"] for r in rows})

    section("A. Files and distinct contents, by kind (from the CSV)")
    lines = []
    for k in kinds:
        ks = [r for r in rows if r["kind"] == k]
        shas = {r["sha256"] for r in ks}
        lines.append((k, len(ks), len(shas), human(sum(r["size"] for r in ks)),
                      human(statistics.median(r["size"] for r in ks))))
    lines.append(("ALL", len(rows), len(by), human(sum(r["size"] for r in rows)),
                  human(statistics.median(r["size"] for r in rows))))
    table(("kind", "files", "distinct sha256", "bytes on disk", "median file"), lines)
    print("  The sample count is the distinct-sha256 figure. Never the file count.")

    section("B. Contents that arrived by more than one route")
    both = [c for c in by.values() if len(c["kinds"]) > 1]
    if not both:
        print("  none -- no content is both a hash-named file and a redirect capture")
    else:
        lines = [(c["row"]["sha256"][:12], human(c["row"]["size"]), magic_class(c["row"]["magic"]),
                  " + ".join("%s x%d" % kv for kv in sorted(c["kinds"].items())))
                 for c in sorted(both, key=lambda c: -c["copies"])]
        table(("sha256 (prefix)", "size", "class", "routes"), lines)

    section("C. ELF binaries by architecture -- distinct contents, then files")
    elf = [c for c in by.values() if c["row"]["elf"] == 1]
    arch = defaultdict(list)
    for c in elf:
        arch[c["row"]["elf_machine"] or "?"].append(c)
    lines = []
    for a, cs in sorted(arch.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        files = sum(c["copies"] for c in cs)
        strip = sum(1 for c in cs if (c["row"]["elf_stripped"] or "") == "1")
        nosec = sum(1 for c in cs if (c["row"]["elf_no_sections"] or "") == "1")
        trunc = sum(1 for c in cs if (c["row"]["elf_truncated"] or "") == "1")
        hn = sum(c["kinds"].get("hash-named", 0) for c in cs)
        rd = sum(c["kinds"].get("shell-redirection", 0) for c in cs)
        lines.append((a, len(cs), files, hn, rd, strip, nosec, trunc,
                      human(statistics.median(c["row"]["size"] for c in cs))))
    lines.append(("ALL ELF", len(elf), sum(c["copies"] for c in elf),
                  sum(l[3] for l in lines), sum(l[4] for l in lines),
                  sum(l[5] for l in lines), sum(l[6] for l in lines), sum(l[7] for l in lines), ""))
    table(("arch", "distinct", "files", "as hash-named", "as redirect", "stripped",
           "no sections", "truncated", "median size"), lines)
    print("  'stripped' and 'no sections' are counted over distinct contents; a binary")
    print("  with no section table is counted under both only if the parser said so.")

    section("D. Non-ELF contents by file(1) class -- distinct contents, then files")
    non = [c for c in by.values() if c["row"]["elf"] != 1]
    cls = defaultdict(list)
    for c in non:
        cls[magic_class(c["row"]["magic"])].append(c)
    lines = [(k, len(cs), sum(c["copies"] for c in cs),
              human(statistics.median(c["row"]["size"] for c in cs)))
             for k, cs in sorted(cls.items(), key=lambda kv: (-len(kv[1]), kv[0]))]
    lines.append(("ALL non-ELF", len(non), sum(c["copies"] for c in non), ""))
    table(("class", "distinct", "files", "median size"), lines)

    section("E. Size distribution of distinct contents")
    lines = []
    for label, test in SIZE_BUCKETS:
        cs = [c for c in by.values() if test(c["row"]["size"])]
        lines.append((label, len(cs), sum(c["copies"] for c in cs),
                      sum(1 for c in cs if c["row"]["elf"] == 1)))
    table(("size", "distinct", "files", "of which ELF"), lines)
    big = sorted((c for c in by.values() if c["row"]["features_bytes"] < c["row"]["size"]),
                 key=lambda c: -c["row"]["size"])
    if big:
        print("  features computed over a prefix for %d contents (features_bytes < size):" % len(big))
        for c in big:
            print("    %s  %s on disk, %s read, %s" % (c["row"]["sha256"][:12], human(c["row"]["size"]),
                                                   human(c["row"]["features_bytes"]),
                                                   (c["row"]["elf_machine"] or magic_class(c["row"]["magic"]))))

    section("F. Entropy of distinct ELF contents (whole file, bits per byte)")
    lines = []
    for label, lo, hi in ENTROPY_BANDS:
        cs = [c for c in elf if c["row"]["ent_total"] is not None and lo <= c["row"]["ent_total"] < hi]
        lines.append((label, len(cs), sum(c["copies"] for c in cs)))
    table(("band", "distinct", "files"), lines)
    print("  High entropy over the whole file is consistent with packing or compression;")
    print("  it is not proof of it, and nothing here was unpacked or run.")

    section("G. The most-copied contents (same bytes, many files)")
    top = sorted(by.values(), key=lambda c: -c["copies"])[:12]
    lines = [(c["row"]["sha256"][:12], c["copies"], human(c["row"]["size"]),
              (c["row"]["elf_machine"] if c["row"]["elf"] == 1 else magic_class(c["row"]["magic"])),
              " + ".join("%s x%d" % kv for kv in sorted(c["kinds"].items())))
             for c in top]
    table(("sha256 (prefix)", "copies", "size", "what", "routes"), lines)
    once = sum(1 for c in by.values() if c["copies"] == 1)
    print("  %d of %d distinct contents were captured exactly once." % (once, len(by)))


# ---------------------------------------------------------------- --dir dates

def report_dir(rows, by, directory):
    section("H. When the files arrived (modification times; files stat()ed, not opened)")
    name_to = {r["name"]: r for r in rows}
    seen_first = {}
    per_week = defaultdict(lambda: Counter())
    first = last = None
    missing = 0
    stamped = []
    for name, r in name_to.items():
        p = os.path.join(directory, name)
        try:
            m = os.stat(p).st_mtime
        except OSError:
            missing += 1
            continue
        t = dt.datetime.fromtimestamp(m, dt.timezone.utc)
        stamped.append((t, r))
    stamped.sort(key=lambda x: x[0])
    for t, r in stamped:
        wk = "%d-W%02d" % t.isocalendar()[:2]
        per_week[wk]["files"] += 1
        per_week[wk][r["kind"]] += 1
        if r["sha256"] not in seen_first:
            seen_first[r["sha256"]] = t
            per_week[wk]["new contents"] += 1
        first = first or t
        last = t
    if missing:
        print("  %d CSV rows had no file at the given path (renamed or removed since the CSV)" % missing)
    if not stamped:
        print("  no files found under %s" % directory)
        return
    print("  first file  %s UTC" % first.strftime("%Y-%m-%d %H:%M"))
    print("  last file   %s UTC" % last.strftime("%Y-%m-%d %H:%M"))
    for k in sorted({r["kind"] for r in rows}):
        ks = [t for t, r in stamped if r["kind"] == k]
        if ks:
            print("  %-18s first %s   last %s   (%d files)" % (k, ks[0].strftime("%Y-%m-%d %H:%M"),
                                                               ks[-1].strftime("%Y-%m-%d %H:%M"), len(ks)))
    kinds = sorted({r["kind"] for r in rows})
    lines = [(wk,) + tuple(c.get(k, 0) for k in kinds) + (c["files"], c["new contents"])
             for wk, c in sorted(per_week.items())]
    table(("ISO week",) + tuple(kinds) + ("files", "contents first seen"), lines)
    print("  A modification time is when the capture finished, as the filesystem recorded it.")
    print("  Cowrie overwrites a hash-named file on a re-capture, so for hash-named files")
    print("  the time shown is the LAST capture of that content, not the first.")


# ---------------------------------------------------------------- --db joins

def report_db(rows, by, db_path):
    con = sqlite3.connect("file:%s?mode=ro" % db_path, uri=True)
    cur = con.cursor()

    section("I. The four kinds of file event (query 13's rule, from the database)")
    kind_sql = """
      CASE WHEN eventid = 'cowrie.session.file_upload'                 THEN 'pushed over scp'
           WHEN json_extract(raw,'$.url') IS NOT NULL
                AND eventid = 'cowrie.session.file_download'           THEN 'FETCHED - outbound'
           WHEN json_extract(raw,'$.url') IS NOT NULL                  THEN 'fetch failed - outbound'
           ELSE 'shell redirection' END"""
    cur.execute("""
      SELECT %s AS kind, COUNT(*), COUNT(DISTINCT session), COUNT(DISTINCT src_ip),
             COUNT(DISTINCT json_extract(raw,'$.shasum')),
             COUNT(DISTINCT json_extract(raw,'$.url')),
             substr(MIN(ts),1,16), substr(MAX(ts),1,16)
        FROM v_events WHERE eventid LIKE 'cowrie.session.file_%%'
       GROUP BY 1 ORDER BY 2 DESC""" % kind_sql)
    lines = [(k, ev, se, so, sh, u, f, l) for k, ev, se, so, sh, u, f, l in cur.fetchall()]
    table(("kind", "events", "sessions", "sources", "distinct shasum", "distinct URLs",
           "first", "last"), lines)
    print("  Sources and URLs are COUNTS. The rules of engagement keep the values out of")
    print("  every document; the database keeps them for the analysis that needs them.")

    section("J. Hash-named files on disk against the shasums the database recorded")
    cur.execute("""
      SELECT json_extract(raw,'$.shasum') AS sha, %s AS kind, MIN(ts), MAX(ts),
             COUNT(*), COUNT(DISTINCT src_ip)
        FROM v_events
       WHERE eventid LIKE 'cowrie.session.file_%%' AND json_extract(raw,'$.shasum') IS NOT NULL
       GROUP BY 1, 2""" % kind_sql)
    db_sha = defaultdict(list)
    for sha, kind, f, l, n, s in cur.fetchall():
        db_sha[sha].append((kind, f, l, n, s))
    disk_hn = {c["row"]["sha256"] for c in by.values() if c["kinds"].get("hash-named")}
    disk_all = set(by)
    known = disk_hn & set(db_sha)
    print("  hash-named contents on disk            %d" % len(disk_hn))
    print("  of those, with a shasum in the database %d" % len(known))
    print("  on disk, unknown to the database        %d" % len(disk_hn - set(db_sha)))
    print("  in the database, not on disk            %d" % len(set(db_sha) - disk_all))
    by_kind = Counter()
    for sha in known:
        for kind, f, l, n, s in db_sha[sha]:
            by_kind[kind] += 1
    for k, n in sorted(by_kind.items(), key=lambda kv: -kv[1]):
        print("    %-26s %d contents" % (k, n))
    print("  (a content can appear under two kinds if it was both fetched and pushed)")

    section("K. Fetched files -- the 29 September problem, as it stands in the data")
    cur.execute("""
      SELECT substr(MIN(ts),1,16), substr(MAX(ts),1,16), COUNT(*), COUNT(DISTINCT session),
             COUNT(DISTINCT src_ip), COUNT(DISTINCT json_extract(raw,'$.shasum')),
             COUNT(DISTINCT json_extract(raw,'$.url'))
        FROM v_events WHERE eventid = 'cowrie.session.file_download'
         AND json_extract(raw,'$.url') IS NOT NULL""")
    f, l, ev, se, so, sh, u = cur.fetchone()
    print("  first %s   last %s   fetches %d   sessions %d   sources %d   distinct files %d   distinct URLs %d"
          % (f, l, ev, se, so, sh, u))
    cur.execute("""
      SELECT COUNT(*) FROM v_events WHERE eventid = 'cowrie.session.file_download'
         AND json_extract(raw,'$.url') IS NOT NULL AND ts > '2026-09-29T12:00'""")
    print("  fetches after the block went in (29 Sep 12:00 UTC): %d   <- must be 0" % cur.fetchone()[0])
    fetched = {sha for sha, ks in db_sha.items() if any(k == "FETCHED - outbound" for k, *_ in ks)}
    print("  fetched contents on disk today: %d of %d (captured files are never deleted; the rest were"
          " recorded with a shasum but no file survives under it)" % (len(fetched & disk_all), len(fetched)))

    section("L. File events per week (SQLite %W weeks), as counts")
    cur.execute("""
      SELECT strftime('%%Y-W%%W', ts) AS wk, %s AS kind, COUNT(*), COUNT(DISTINCT session),
             COUNT(DISTINCT src_ip), COUNT(DISTINCT json_extract(raw,'$.shasum'))
        FROM v_events WHERE eventid LIKE 'cowrie.session.file_%%'
       GROUP BY 1, 2 ORDER BY 1, 2""" % kind_sql)
    lines = cur.fetchall()
    table(("week", "kind", "events", "sessions", "sources", "distinct shasum"), lines)
    print("  (SQLite's %W weeks start on Monday and are numbered from the year's first Monday;")
    print("   they are close to, not identical with, the ISO weeks in section H.)")
    con.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--csv", required=True, help="file-features.csv from features-files.py")
    ap.add_argument("--dir", default=None, help="captured-files directory, for modification times (stat only)")
    ap.add_argument("--db", default=None, help="decoy.sqlite, opened read-only, for the file-event joins")
    a = ap.parse_args()

    rows = load(a.csv)
    if not rows:
        print("the CSV has no rows; nothing to inventory", file=sys.stderr)
        return 2
    by = contents(rows)
    print("inventory as at %s UTC, from %s (%d rows, %d distinct sha256)"
          % (dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M"), a.csv, len(rows), len(by)))
    report_csv(rows, by)
    if a.dir:
        report_dir(rows, by, a.dir)
    if a.db:
        report_db(rows, by, a.db)
    print()
    print("  Nothing was executed. No captured file was opened. No address or URL was printed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
