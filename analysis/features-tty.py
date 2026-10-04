#!/usr/bin/env python3
"""
features-tty.py -- keystroke timing features from Cowrie's TTY recordings.

    python3 features-tty.py --dir <tty dir> --out tty-features.csv
    python3 features-tty.py --dir <tty dir> --verify          # parse ONE file, loudly

WHERE TO RUN IT
---------------
Either on the sensor, or on the laptop against an extracted backup -- the TTY
recordings are inside the tarball `backup.ps1` pulls down, under
`home/cowrie/cowrie/var/lib/cowrie/tty/`. The laptop is the better choice: this
is pure parsing, it needs no access to anything live, and the recordings are
already safe in the backups.

WHAT IT PRODUCES
----------------
One row per recording:

    file, session, n_input_bytes, duration_s
    iki_mean, iki_median, iki_sd, iki_p10, iki_p90, iki_max
    frac_under_5ms, frac_under_20ms, frac_over_1s
    n_backspace, n_arrow, n_tab, n_enter
    uniformity                 sd / mean -- near zero means a machine inserting
                               a fixed delay to look like a person
    weak_label                 scripted | typed | unlabelled

"iki" is inter-keystroke interval: the gap between one keystroke arriving and
the next.

THE WEAK LABEL IS A GUESS AND IS LABELLED AS ONE
------------------------------------------------
    scripted    > 95% of intervals under 5 ms          (a paste or a pipe)
    typed       contains a backspace AND median > 80ms (a person correcting)
    unlabelled  everything else

The unlabelled rows are the interesting ones, not a residue to be tidied away.
A tool with randomised delays and a person using tab-completion both land there.
Report how many rows each label got; if "scripted" is 95% of the file, the
honest finding is that almost nothing here was typed by hand.

ON THE FILE FORMAT -- READ THIS BEFORE TRUSTING ANY NUMBER
----------------------------------------------------------
Cowrie's TTY log is its own binary format: a 24-byte header per record, six
little-endian int32 fields (op, direction, seconds, microseconds, length, pad),
followed by `length` bytes of payload for a write record. That layout is taken
from cowrie/core/ttylog.py and it has been stable for a long time, but it is not
a documented interface and it is not guaranteed for your build
(3.0.16.dev4+g9dc1ea8f3).

So this script validates rather than assumes. Every record's fields are checked
for sanity and a file that does not parse cleanly is REPORTED, not silently
skipped or half-read.

Before using the output for anything, run --verify on one recording and compare
what it prints against Cowrie's own player:

    /home/cowrie/cowrie/bin/playlog -f <that same file>

If the byte counts and the timestamps do not line up, the format differs in your
build and the parser needs fixing -- which is a normal outcome, not a failure.
A parser that quietly produced plausible-looking nonsense would be the bad one.
"""

import argparse
import csv
import os
import statistics
import struct
import sys

HDR = struct.Struct("<iiiiii")
HDR_LEN = HDR.size  # 24

OP_OPEN, OP_WRITE, OP_CLOSE = 1, 2, 3
DIR_INPUT, DIR_OUTPUT, DIR_INTERACT = 1, 2, 3

# A single record longer than this is taken as evidence the layout is wrong,
# rather than as a very large keystroke.
SANE_MAX_RECORD = 4 * 1024 * 1024

BACKSPACE = {0x08, 0x7f}
TAB = {0x09}
ENTER = {0x0d, 0x0a}


def parse(path, strict=True):
    """Yield (timestamp, direction, payload). Raises ValueError on a bad parse."""
    with open(path, "rb") as fh:
        blob = fh.read()

    off, n = 0, len(blob)
    records = 0
    while off + HDR_LEN <= n:
        op, direction, sec, usec, length, _pad = HDR.unpack_from(blob, off)
        off += HDR_LEN

        if op not in (OP_OPEN, OP_WRITE, OP_CLOSE):
            raise ValueError("record %d: op=%d is not 1, 2 or 3 at offset %d "
                             "-- the header layout does not match this build"
                             % (records, op, off - HDR_LEN))
        if length < 0 or length > SANE_MAX_RECORD:
            raise ValueError("record %d: length=%d is not plausible at offset %d"
                             % (records, length, off - HDR_LEN))
        if op == OP_WRITE and direction not in (DIR_INPUT, DIR_OUTPUT, DIR_INTERACT):
            raise ValueError("record %d: direction=%d on a write record"
                             % (records, direction))
        if usec < 0 or usec >= 1_000_000:
            raise ValueError("record %d: usec=%d out of range" % (records, usec))

        payload = b""
        if length:
            if off + length > n:
                if strict:
                    raise ValueError("record %d claims %d bytes but only %d remain "
                                     "-- file is truncated or the layout is wrong"
                                     % (records, length, n - off))
                payload = blob[off:n]
                off = n
            else:
                payload = blob[off:off + length]
                off += length

        records += 1
        if op == OP_WRITE:
            yield (sec + usec / 1_000_000.0, direction, payload)

    if records == 0:
        raise ValueError("no records at all -- empty or not a Cowrie TTY log")
    if off != n:
        raise ValueError("%d trailing bytes after the last record -- "
                         "the layout does not match cleanly" % (n - off))


def pct(values, p):
    if not values:
        return 0.0
    s = sorted(values)
    k = max(0, min(len(s) - 1, int(round((p / 100.0) * (len(s) - 1)))))
    return s[k]


def features(path):
    stamps = []
    keybytes = []
    for ts, direction, payload in parse(path):
        if direction != DIR_INPUT:
            continue
        # One record can carry several bytes -- a paste arrives as one chunk.
        # The arrival time is the record's, so bytes within a chunk share it,
        # which is exactly the signal: zero intervals mean machine input.
        for b in payload:
            stamps.append(ts)
            keybytes.append(b)

    if len(stamps) < 2:
        return None

    ikis = [b - a for a, b in zip(stamps, stamps[1:])]
    ikis = [x for x in ikis if x >= 0]
    if not ikis:
        return None

    mean = statistics.fmean(ikis)
    sd = statistics.pstdev(ikis) if len(ikis) > 1 else 0.0
    median = statistics.median(ikis)

    n_bs = sum(1 for b in keybytes if b in BACKSPACE)
    n_tab = sum(1 for b in keybytes if b in TAB)
    n_enter = sum(1 for b in keybytes if b in ENTER)
    # Arrow keys arrive as ESC [ A/B/C/D.
    n_arrow = 0
    for i in range(len(keybytes) - 2):
        if keybytes[i] == 0x1b and keybytes[i + 1] == 0x5b and keybytes[i + 2] in (65, 66, 67, 68):
            n_arrow += 1

    frac5 = sum(1 for x in ikis if x < 0.005) / len(ikis)
    frac20 = sum(1 for x in ikis if x < 0.020) / len(ikis)
    frac1s = sum(1 for x in ikis if x > 1.0) / len(ikis)

    if frac5 > 0.95:
        label = "scripted"
    elif n_bs > 0 and median > 0.080:
        label = "typed"
    else:
        label = "unlabelled"

    return {
        "file": os.path.basename(path),
        "session": os.path.basename(path).split("-")[-1].split(".")[0],
        "n_input_bytes": len(keybytes),
        "duration_s": round(stamps[-1] - stamps[0], 3),
        "iki_mean": round(mean, 6),
        "iki_median": round(median, 6),
        "iki_sd": round(sd, 6),
        "iki_p10": round(pct(ikis, 10), 6),
        "iki_p90": round(pct(ikis, 90), 6),
        "iki_max": round(max(ikis), 6),
        "frac_under_5ms": round(frac5, 4),
        "frac_under_20ms": round(frac20, 4),
        "frac_over_1s": round(frac1s, 4),
        "n_backspace": n_bs,
        "n_arrow": n_arrow,
        "n_tab": n_tab,
        "n_enter": n_enter,
        "uniformity": round(sd / mean, 4) if mean > 0 else 0,
        "weak_label": label,
    }


def verify(path):
    print()
    print("verifying the parse of a single recording")
    print("  file: %s" % path)
    print()
    try:
        recs = list(parse(path))
    except ValueError as exc:
        print("  PARSE FAILED: %s" % exc)
        print()
        print("  This means the header layout in this Cowrie build differs from")
        print("  the one assumed here. That is a normal outcome. Do not use any")
        print("  output from this script until it is fixed.")
        print()
        return 1

    inp = [r for r in recs if r[1] == DIR_INPUT]
    out = [r for r in recs if r[1] == DIR_OUTPUT]
    print("  write records        %d" % len(recs))
    print("    input direction    %d  (%d bytes)" % (len(inp), sum(len(r[2]) for r in inp)))
    print("    output direction   %d  (%d bytes)" % (len(out), sum(len(r[2]) for r in out)))
    if recs:
        print("  first timestamp      %.6f" % recs[0][0])
        print("  last timestamp       %.6f" % recs[-1][0])
        print("  span                 %.3f s" % (recs[-1][0] - recs[0][0]))
    print()
    print("  first 120 bytes of input, as text:")
    joined = b"".join(r[2] for r in inp)[:120]
    print("    %r" % joined)
    print()
    print("  NOW CROSS-CHECK. Run Cowrie's own player on the same file:")
    print("    /home/cowrie/cowrie/bin/playlog -f %s" % path)
    print("  The input bytes above should appear in what it replays, and the")
    print("  span should match its running time. If they do not, this parser")
    print("  is wrong and the features are meaningless.")
    print()
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dir", required=True, help="directory of Cowrie .log TTY files")
    ap.add_argument("--out", default=None, help="CSV to write")
    ap.add_argument("--verify", action="store_true",
                    help="parse one file and print what was found, for cross-checking")
    ap.add_argument("--file", default=None,
                    help="with --verify, the recording to check. Default is the "
                         "largest one, which is the most likely to be a real "
                         "interactive session rather than a stub.")
    args = ap.parse_args()

    if not os.path.isdir(args.dir):
        sys.exit("not a directory: %s" % args.dir)

    files = sorted(os.path.join(args.dir, n) for n in os.listdir(args.dir)
                   if os.path.isfile(os.path.join(args.dir, n)))
    if not files:
        sys.exit("NOTHING MATCHED in %s -- refusing to report a successful run "
                 "on an empty directory." % args.dir)

    if args.verify:
        if args.file:
            target = args.file if os.path.isabs(args.file) else os.path.join(args.dir, args.file)
            if not os.path.isfile(target):
                sys.exit("no such recording: %s" % target)
        else:
            target = max(files, key=os.path.getsize)
        sys.exit(verify(target))

    if not args.out:
        sys.exit("--out is required unless you pass --verify")

    rows, failed, too_short = [], [], []
    for path in files:
        try:
            f = features(path)
        except ValueError as exc:
            failed.append((os.path.basename(path), str(exc)))
            continue
        if f is None:
            too_short.append(os.path.basename(path))
            continue
        rows.append(f)

    if not rows:
        sys.exit("no recording yielded features. %d failed to parse, %d had too "
                 "little input. Run --verify before going further."
                 % (len(failed), len(too_short)))

    cols = list(rows[0].keys())
    with open(args.out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)

    labels = {}
    for r in rows:
        labels[r["weak_label"]] = labels.get(r["weak_label"], 0) + 1

    print()
    print("wrote %s" % args.out)
    print("  recordings found      %d" % len(files))
    print("  features extracted    %d" % len(rows))
    print("  failed to parse       %d" % len(failed))
    for n, e in failed:
        print("    %s: %s" % (n, e))
    print("  too little input      %d" % len(too_short))
    print()
    for k in ("typed", "unlabelled", "scripted"):
        print("  weak label %-12s %d" % (k, labels.get(k, 0)))
    print()
    print("  The unlabelled rows are the finding. Read them by hand.")
    print("  If 'typed' is 0, say so plainly -- that is a result, not a gap.")
    print()
    if failed:
        print("  SOMETHING FAILED TO PARSE. Run --verify and cross-check against")
        print("  playlog before quoting any number from this CSV.")
        print()


if __name__ == "__main__":
    main()
