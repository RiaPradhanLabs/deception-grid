#!/usr/bin/env python3
"""
features-tty.py -- per-recording command timeline from Cowrie's TTY recordings.

    python3 features-tty.py --dir <tty dir> --out tty-timeline.csv
    python3 features-tty.py --dir <tty dir> --verify          # parse ONE file, loudly
    python3 features-tty.py --dir <tty dir> --census          # parse ALL, report shape

WHERE TO RUN IT
---------------
Either on the sensor, or on the laptop against an extracted backup -- the TTY
recordings are inside the tarball `backup.ps1` pulls down, under
`home/cowrie/cowrie/var/lib/cowrie/tty/`. The laptop is the better choice: this
is pure parsing, it needs no access to anything live, and the recordings are
already safe in the backups.

WHAT THIS SCRIPT IS NOT
-----------------------
It is NOT a keystroke-timing tool, and an earlier version of it was written as
one. That was wrong, and the reason is recorded here rather than deleted,
because the measurement is a finding in its own right.

Measured over all 130 recordings on decoy-01, 5 October 2026 (the tty directory
also holds a .gitignore, which is skipped by name, not by a silent glob):

    input records                           593   (67,669 bytes)
    ... ending in CR or LF                  373
    ... carrying exactly one character        5   -- 'e' 'x' 'i' 't' and 'w'
    ... carrying a bare newline only        103
    ... containing a backspace                1

Mean input record: 114 bytes. Cowrie writes one record per chunk arriving on
the wire, so a 114-byte record is a WHOLE COMMAND LINE pasted or piped in, not
a keypress. The only characters ever delivered one at a time in this dataset
spell `exit`, plus a single `w`.

Keystroke dynamics needs per-character arrival times. This dataset contains
five characters' worth. So the intervals this script reports are gaps between
COMMANDS, and they are named that way -- `icg`, inter-command gap. Calling them
keystroke intervals would have been a plausible number measuring something
other than its name.

WHAT IT PRODUCES
----------------
One row per recording:

    file                 join key -- the Cowrie JSON `ttylog` field holds this
                         same basename, which is how a row links to a session
    n_input_records      chunks the visitor sent
    n_command_lines      input records ending in CR or LF
    n_input_bytes        total bytes the visitor sent
    n_output_records     chunks the honeypot sent back
    n_output_bytes       total bytes the honeypot sent back
    duration_s           last record's timestamp minus the first's
    n_icg                intervals available: n_input_records - 1, or 0
    icg_median_s         gap between consecutive commands
    icg_mean_s, icg_min_s, icg_max_s, icg_p10_s, icg_p90_s
    input_bytes_mean     n_input_bytes / n_input_records
    input_bytes_max      the largest single chunk
    n_single_char        input records of exactly one printable character
    n_bare_newline       input records that are only CR or LF
    n_backspace          input records containing 0x08 or 0x7f
    frac_icg_under_20ms  near-zero gaps: one command following another with no
                         human pause at all
    frac_icg_over_1s     gaps over a second

There is deliberately NO label column. The previous version assigned
"typed" / "scripted" / "unlabelled" from a backspace count and an interval
threshold; with one backspace in the whole dataset and no per-character timing,
those labels would have been noise wearing a confident name. Rows with
n_icg == 0 are reported, not dropped -- 62 of the 130 recordings are a single
pasted command, and that proportion is itself the result.

ON THE FILE FORMAT
------------------
Cowrie's TTY log is its own undocumented binary format: a 24-byte header per
record, six little-endian int32 fields, then `length` bytes of payload on a
write record. The field order below was NOT taken from the source -- it was
derived from the bytes of a real recording on 5 October 2026, after an assumed
layout failed:

    offset   0   op          1 = open, 2 = close, 3 = write
    offset   4   unused      always 0 in every record observed
    offset   8   length      payload bytes following the header
    offset  12   direction   1 = input, 2 = output, 3 = interact
    offset  16   sec         Unix seconds
    offset  20   usec        microseconds

Confirmed against all 130 recordings: every file walks to its exact end with
zero trailing bytes, and yields exactly one open record and one close record.
A wrong field order desynchronises within a handful of records, so reaching EOF
on the byte across 130 files is a strong check rather than a lucky one.

Still worth cross-checking the content against Cowrie's own player:

    /home/cowrie/cowrie/bin/playlog -f <that same file>

A parser that quietly produced plausible-looking nonsense would be the bad one.
"""

import argparse
import csv
import os
import statistics
import struct
import sys

HDR = struct.Struct("<iiiiii")   # op, unused, length, direction, sec, usec
HDR_LEN = HDR.size               # 24

OP_OPEN, OP_CLOSE, OP_WRITE = 1, 2, 3
DIR_INPUT, DIR_OUTPUT, DIR_INTERACT = 1, 2, 3

# A visitor's input arrives on the DIR_INPUT channel, and occasionally on
# DIR_INTERACT (54 records of 593 in the 5 October dataset). Both are the
# visitor; neither is the honeypot's own output.
DIR_FROM_VISITOR = (DIR_INPUT, DIR_INTERACT)

# A single record longer than this is taken as evidence the layout is wrong,
# rather than as a very large chunk.
SANE_MAX_RECORD = 4 * 1024 * 1024

BACKSPACE = {0x08, 0x7F}
NEWLINE = {0x0A, 0x0D}


def parse(path):
    """Yield (timestamp, op, direction, payload). Raises ValueError on a bad parse."""
    with open(path, "rb") as fh:
        blob = fh.read()

    off, n, records = 0, len(blob), 0
    while off + HDR_LEN <= n:
        op, unused, length, direction, sec, usec = HDR.unpack_from(blob, off)
        here = off
        off += HDR_LEN

        if op not in (OP_OPEN, OP_CLOSE, OP_WRITE):
            raise ValueError("record %d: op=%d is not 1, 2 or 3 at offset %d "
                             "-- the header layout does not match this build"
                             % (records, op, here))
        if length < 0 or length > SANE_MAX_RECORD:
            raise ValueError("record %d: length=%d is not plausible at offset %d"
                             % (records, length, here))
        if op == OP_WRITE and direction not in (DIR_INPUT, DIR_OUTPUT, DIR_INTERACT):
            raise ValueError("record %d: direction=%d on a write record at offset %d"
                             % (records, direction, here))
        if usec < 0 or usec >= 1_000_000:
            raise ValueError("record %d: usec=%d out of range at offset %d"
                             % (records, usec, here))

        payload = b""
        if length:
            if off + length > n:
                raise ValueError("record %d claims %d bytes but only %d remain "
                                 "-- file is truncated or the layout is wrong"
                                 % (records, length, n - off))
            payload = blob[off:off + length]
            off += length

        records += 1
        yield (sec + usec / 1_000_000.0, op, direction, payload)

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


def timeline(path):
    """One row per recording. Never returns None -- a recording with a single
    input record is a data point, not a reject."""
    stamps_all = []
    visitor = []          # (timestamp, payload)
    out_records = 0
    out_bytes = 0

    for ts, op, direction, payload in parse(path):
        stamps_all.append(ts)
        if op != OP_WRITE:
            continue
        if direction in DIR_FROM_VISITOR:
            visitor.append((ts, payload))
        elif direction == DIR_OUTPUT:
            out_records += 1
            out_bytes += len(payload)

    in_bytes = sum(len(p) for _, p in visitor)
    gaps = [b - a for (a, _), (b, _) in zip(visitor, visitor[1:])]
    gaps = [g for g in gaps if g >= 0]

    n_single = sum(1 for _, p in visitor
                   if len(p) == 1 and p[0] not in NEWLINE)
    n_bare_nl = sum(1 for _, p in visitor
                    if len(p) == 1 and p[0] in NEWLINE)
    n_cmd = sum(1 for _, p in visitor
                if p and p[-1] in NEWLINE)
    n_bs = sum(1 for _, p in visitor
               if any(b in BACKSPACE for b in p))

    row = {
        "file": os.path.basename(path),
        "n_input_records": len(visitor),
        "n_command_lines": n_cmd,
        "n_input_bytes": in_bytes,
        "n_output_records": out_records,
        "n_output_bytes": out_bytes,
        "duration_s": round(stamps_all[-1] - stamps_all[0], 3) if stamps_all else 0.0,
        "n_icg": len(gaps),
        "icg_median_s": round(statistics.median(gaps), 6) if gaps else "",
        "icg_mean_s": round(statistics.fmean(gaps), 6) if gaps else "",
        "icg_min_s": round(min(gaps), 6) if gaps else "",
        "icg_max_s": round(max(gaps), 6) if gaps else "",
        "icg_p10_s": round(pct(gaps, 10), 6) if gaps else "",
        "icg_p90_s": round(pct(gaps, 90), 6) if gaps else "",
        "input_bytes_mean": round(in_bytes / len(visitor), 2) if visitor else "",
        "input_bytes_max": max((len(p) for _, p in visitor), default=0),
        "n_single_char": n_single,
        "n_bare_newline": n_bare_nl,
        "n_backspace": n_bs,
        "frac_icg_under_20ms": (round(sum(1 for g in gaps if g < 0.020) / len(gaps), 4)
                                if gaps else ""),
        "frac_icg_over_1s": (round(sum(1 for g in gaps if g > 1.0) / len(gaps), 4)
                             if gaps else ""),
    }
    return row


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
        print("  The header layout in this Cowrie build differs from the one")
        print("  documented at the top of this script. Dump the first 64 bytes")
        print("  and find where the Unix timestamp lands before changing HDR.")
        print("  Do not use any output from this script until it is fixed.")
        print()
        return 1

    opens = [r for r in recs if r[1] == OP_OPEN]
    closes = [r for r in recs if r[1] == OP_CLOSE]
    inp = [r for r in recs if r[1] == OP_WRITE and r[2] in DIR_FROM_VISITOR]
    out = [r for r in recs if r[1] == OP_WRITE and r[2] == DIR_OUTPUT]

    print("  records parsed to EOF  %d" % len(recs))
    print("    open / close         %d / %d  (expect 1 and 1)" % (len(opens), len(closes)))
    print("    from the visitor     %d  (%d bytes)" % (len(inp), sum(len(r[3]) for r in inp)))
    print("    from the honeypot    %d  (%d bytes)" % (len(out), sum(len(r[3]) for r in out)))
    if recs:
        print("  first timestamp        %.6f" % recs[0][0])
        print("  last timestamp         %.6f" % recs[-1][0])
        print("  span                   %.3f s" % (recs[-1][0] - recs[0][0]))
    print()
    if len(opens) != 1 or len(closes) != 1:
        print("  WARNING: a recording should hold exactly one open and one close.")
        print("  Anything else means the op values are being misread.")
        print()

    print("  every chunk the visitor sent, in order:")
    for i, (ts, _, _, p) in enumerate(inp):
        gap = "" if i == 0 else "  +%.3fs" % (ts - inp[i - 1][0])
        print("    %2d  %4d bytes%s  %r" % (i, len(p), gap, p[:60]))
    print()
    print("  NOW CROSS-CHECK. Run Cowrie's own player on the same file:")
    print("    /home/cowrie/cowrie/bin/playlog -f %s" % path)
    print("  The chunks above should appear in what it replays, and the span")
    print("  should match its running time. If they do not, this parser is")
    print("  wrong and every number it produces is meaningless.")
    print()
    return 0


def census(files):
    """Dataset-level shape. This is the measurement that decided the TTY data
    cannot support keystroke timing, so the tool reports it rather than
    leaving it in a document somewhere."""
    rows, failed = [], []
    for path in files:
        try:
            rows.append(timeline(path))
        except ValueError as exc:
            failed.append((os.path.basename(path), str(exc)))

    if not rows:
        print("no recording parsed. %d failed." % len(failed))
        return 1

    tot_in = sum(r["n_input_records"] for r in rows)
    tot_b = sum(r["n_input_bytes"] for r in rows)
    tot_gaps = sum(r["n_icg"] for r in rows)
    sc = sum(r["n_single_char"] for r in rows)
    nl = sum(r["n_bare_newline"] for r in rows)
    bs = sum(r["n_backspace"] for r in rows)
    cmd = sum(r["n_command_lines"] for r in rows)

    buckets = {"0": 0, "1": 0, "2-9": 0, "10-49": 0, "50+": 0}
    for r in rows:
        n = r["n_input_records"]
        buckets["0" if n == 0 else "1" if n == 1 else "2-9" if n < 10
                else "10-49" if n < 50 else "50+"] += 1

    print()
    print("recordings parsed        %d" % len(rows))
    print("failed to parse          %d" % len(failed))
    for n, e in failed:
        print("    %s: %s" % (n, e))
    print()
    print("input records            %d  (%d bytes)" % (tot_in, tot_b))
    print("  mean bytes per record  %.1f" % (tot_b / tot_in if tot_in else 0))
    print("  ending in CR or LF     %d" % cmd)
    print("  one character only     %d" % sc)
    print("  a bare newline only    %d" % nl)
    print("  containing a backspace %d" % bs)
    print()
    print("inter-command gaps available  %d" % tot_gaps)
    print()
    print("input records per recording:")
    for k in ("0", "1", "2-9", "10-49", "50+"):
        print("  %-6s : %4d" % (k, buckets[k]))
    print()
    if sc < 20:
        print("  Fewer than 20 single-character records in the whole dataset.")
        print("  Nobody typed. Per-character timing is not available here, and")
        print("  any 'keystroke dynamics' result from this data would be an")
        print("  artefact of pasted command lines. Report that as a finding.")
        print()
    return 1 if failed else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dir", required=True, help="directory of Cowrie TTY recordings")
    ap.add_argument("--out", default=None, help="CSV to write")
    ap.add_argument("--verify", action="store_true",
                    help="parse one recording and print every chunk, for cross-checking")
    ap.add_argument("--census", action="store_true",
                    help="parse all recordings and report the dataset's shape")
    ap.add_argument("--file", default=None,
                    help="with --verify, the recording to check. Default is the "
                         "largest one.")
    args = ap.parse_args()

    if not os.path.isdir(args.dir):
        sys.exit("not a directory: %s" % args.dir)

    names = sorted(n for n in os.listdir(args.dir)
                   if os.path.isfile(os.path.join(args.dir, n)))

    # Cowrie keeps a .gitignore in its tty directory. Dotfiles are housekeeping,
    # not recordings. They are NAMED here rather than silently dropped -- an
    # earlier pass used glob(), which skips dotfiles without saying so, and a
    # real recording arriving under an unexpected name must not be able to hide
    # among the things being skipped.
    skipped = [n for n in names if n.startswith(".")]
    files = [os.path.join(args.dir, n) for n in names if not n.startswith(".")]
    if skipped:
        print("not recordings, skipped: %s" % ", ".join(skipped))

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

    if args.census:
        sys.exit(census(files))

    if not args.out:
        sys.exit("--out is required unless you pass --verify or --census")

    rows, failed = [], []
    for path in files:
        try:
            rows.append(timeline(path))
        except ValueError as exc:
            failed.append((os.path.basename(path), str(exc)))

    if not rows:
        sys.exit("no recording yielded a row. %d failed to parse. "
                 "Run --verify before going further." % len(failed))

    with open(args.out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    no_gap = sum(1 for r in rows if r["n_icg"] == 0)
    print()
    print("wrote %s" % args.out)
    print("  recordings found      %d" % len(files))
    print("  rows written          %d" % len(rows))
    print("  failed to parse       %d" % len(failed))
    for n, e in failed:
        print("    %s: %s" % (n, e))
    print("  rows with no gap      %d  (a single chunk -- kept, not dropped)" % no_gap)
    print()
    print("  Run --census for the dataset-level shape before quoting anything.")
    print()
    if failed:
        print("  SOMETHING FAILED TO PARSE. Run --verify and cross-check against")
        print("  playlog before quoting any number from this CSV.")
        print()
        # Exit non-zero so a scheduled run cannot read this as success.
        sys.exit(1)


if __name__ == "__main__":
    main()
