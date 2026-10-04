#!/usr/bin/env python3
"""
features-files.py -- static features of the captured files, computed ON THE SENSOR.

    sudo python3 features-files.py --out ~/analysis/file-features.csv

WHY THIS EXISTS
---------------
The captured files never leave the VM. That rule is not relaxed for convenience,
so any analysis that needs the file BYTES has to produce its numbers here and
send back a table. Once the machine is deleted on 12 December the files go with
it and this becomes impossible, so the CSV is the only durable artefact.

WHAT IT DOES NOT DO
-------------------
  * It does not execute anything. Every file is opened 'rb' and read as bytes.
  * It does not install anything. Standard library only -- no tlsh, no ssdeep,
    no pyelftools. A honeypot is the last machine on which to add a compiler
    and three C libraries, and a 256-bin byte histogram plus a windowed entropy
    profile clusters near-duplicate binaries perfectly well without them.
  * It does not send anything anywhere. One local CSV, written where you say.
  * It does not open a network connection, so it works for any user, including
    accounts the firewall blocks outbound.

WHAT COMES BACK
---------------
One row per file. Columns:

    path, name, sha256, size, magic, kind
    ent_total, ent_w0 .. ent_w7       Shannon entropy, whole file and 8 windows
    printable_ratio, nul_ratio
    n_strings, str_mean_len, str_max_len
    elf, elf_class, elf_machine, elf_type, elf_stripped, elf_sections
    h000 .. h255                      byte-value histogram, normalised

The histogram and the entropy windows are the clustering features. Everything
before them is description.

STRINGS: the extracted strings are NOT in this CSV. They can contain attacker
URLs and addresses, so they go to a separate file only if you pass --strings,
and that file must not be committed.
"""

import argparse
import csv
import hashlib
import math
import os
import re
import subprocess
import sys

DEFAULT_DIR = "/home/cowrie/cowrie/var/lib/cowrie/downloads"

# A redirection capture is named redir_<uuid> rather than by hash. These are
# mostly not malware at all -- they are the output of a shell redirection the
# writable-directory probe performed -- and counting them as samples is the
# mistake that produced five wrong figures on 29 September. They are kept in the
# CSV but labelled, so they can be excluded by a WHERE clause rather than by
# being silently dropped here.
REDIR = re.compile(r"^redir_[0-9a-f-]{8,}", re.I)
HASHNAME = re.compile(r"^[0-9a-f]{64}$", re.I)

STRING_RE = re.compile(rb"[\x20-\x7e]{4,}")

WINDOWS = 8


def entropy(counts, total):
    if total <= 0:
        return 0.0
    h = 0.0
    for c in counts:
        if c:
            p = c / total
            h -= p * math.log2(p)
    return h


def histogram(data):
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    return counts


def window_entropies(data, n=WINDOWS):
    """Entropy of n equal slices. Packed or appended regions show up as a step."""
    if not data:
        return [0.0] * n
    size = len(data)
    out = []
    for i in range(n):
        lo = (size * i) // n
        hi = (size * (i + 1)) // n
        chunk = data[lo:hi] if hi > lo else b""
        if not chunk:
            out.append(0.0)
        else:
            out.append(entropy(histogram(chunk), len(chunk)))
    return out


def elf_header(data):
    """Parse the ELF header from raw bytes. No library, no execution.

    Returns a dict of the fields worth clustering on. Everything is guarded,
    because a truncated download is a perfectly normal thing to find here.
    """
    out = {
        "elf": 0, "elf_class": "", "elf_machine": "", "elf_type": "",
        "elf_stripped": "", "elf_sections": "",
    }
    if len(data) < 24 or data[:4] != b"\x7fELF":
        return out
    out["elf"] = 1

    ei_class = data[4]
    ei_data = data[5]
    out["elf_class"] = {1: "32", 2: "64"}.get(ei_class, "?")
    little = ei_data == 1

    def u(off, width):
        chunk = data[off:off + width]
        if len(chunk) < width:
            return None
        return int.from_bytes(chunk, "little" if little else "big")

    e_type = u(16, 2)
    e_machine = u(18, 2)

    # Only the machines that actually turn up on an IoT-targeting honeypot.
    machines = {
        2: "sparc", 3: "x86", 8: "mips", 20: "ppc", 21: "ppc64",
        40: "arm", 42: "sh", 43: "sparcv9", 50: "ia64", 62: "x86-64",
        183: "aarch64", 243: "riscv",
    }
    types = {1: "rel", 2: "exec", 3: "dyn", 4: "core"}
    out["elf_machine"] = machines.get(e_machine, str(e_machine) if e_machine is not None else "?")
    out["elf_type"] = types.get(e_type, str(e_type) if e_type is not None else "?")

    # Section headers: offset and count sit at different offsets for 32/64 bit.
    if ei_class == 2:
        e_shoff, e_shnum = u(40, 8), u(60, 2)
    else:
        e_shoff, e_shnum = u(32, 4), u(48, 2)

    if e_shnum is not None:
        out["elf_sections"] = e_shnum
        # A stripped binary conventionally keeps very few sections and no
        # symbol table. Zero section headers is the strongest signal available
        # without walking the table, which is more parsing than this earns.
        out["elf_stripped"] = 1 if (e_shnum == 0 or not e_shoff) else 0
    return out


def file_magic(path):
    """`file -b`, which reads the file; it does not run it."""
    try:
        r = subprocess.run(
            ["file", "-b", "--", path],
            capture_output=True, text=True, timeout=20, check=False,
        )
        return (r.stdout or "").strip()[:200]
    except Exception as exc:
        return "file(1) failed: %s" % exc


def classify(name):
    if REDIR.match(name):
        return "shell-redirection"
    if HASHNAME.match(name):
        return "hash-named"
    return "other"


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dir", default=DEFAULT_DIR, help="directory of captured files")
    ap.add_argument("--out", required=True, help="CSV to write")
    ap.add_argument("--strings", default=None,
                    help="also write extracted strings here. May contain "
                         "attacker URLs and addresses -- do not commit it.")
    ap.add_argument("--max-bytes", type=int, default=16 * 1024 * 1024,
                    help="read at most this much of any one file (default 16MB)")
    args = ap.parse_args()

    if not os.path.isdir(args.dir):
        sys.exit("not a directory: %s\n"
                 "If this is not the sensor, that is the problem -- this script "
                 "is meant to run there." % args.dir)

    names = sorted(n for n in os.listdir(args.dir)
                   if os.path.isfile(os.path.join(args.dir, n)))
    if not names:
        sys.exit("NOTHING MATCHED in %s -- refusing to write an empty CSV.\n"
                 "An empty result here looks exactly like a successful run, "
                 "which is the whole problem." % args.dir)

    cols = (["path", "name", "sha256", "size", "magic", "kind",
             "ent_total"]
            + ["ent_w%d" % i for i in range(WINDOWS)]
            + ["printable_ratio", "nul_ratio",
               "n_strings", "str_mean_len", "str_max_len",
               "elf", "elf_class", "elf_machine", "elf_type",
               "elf_stripped", "elf_sections"]
            + ["h%03d" % i for i in range(256)])

    rows = []
    strings_out = []
    failures = []
    truncated = []

    for name in names:
        path = os.path.join(args.dir, name)
        try:
            size = os.path.getsize(path)
            with open(path, "rb") as fh:
                data = fh.read(args.max_bytes)
            if size > len(data):
                truncated.append((name, size))
        except Exception as exc:
            failures.append((name, str(exc)))
            continue

        counts = histogram(data)
        total = len(data)
        printable = sum(counts[0x20:0x7f])
        strings = STRING_RE.findall(data)
        lens = [len(s) for s in strings]

        row = {
            "path": path,
            "name": name,
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": size,
            "magic": file_magic(path),
            "kind": classify(name),
            "ent_total": round(entropy(counts, total), 6),
            "printable_ratio": round(printable / total, 6) if total else 0,
            "nul_ratio": round(counts[0] / total, 6) if total else 0,
            "n_strings": len(strings),
            "str_mean_len": round(sum(lens) / len(lens), 3) if lens else 0,
            "str_max_len": max(lens) if lens else 0,
        }
        for i, h in enumerate(window_entropies(data)):
            row["ent_w%d" % i] = round(h, 6)
        row.update(elf_header(data))
        for i in range(256):
            row["h%03d" % i] = round(counts[i] / total, 8) if total else 0
        rows.append(row)

        if args.strings:
            for s in strings[:400]:
                strings_out.append((row["sha256"], s.decode("ascii", "replace")))

    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
    with open(args.out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)

    if args.strings:
        with open(args.strings, "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["sha256", "string"])
            w.writerows(strings_out)
        os.chmod(args.strings, 0o600)

    # --- say what happened, including what did not work -------------------
    #
    # Printing only the success count is how a half-finished run passes for a
    # finished one. Every category below is printed whether or not it is empty.
    kinds = {}
    for r in rows:
        kinds[r["kind"]] = kinds.get(r["kind"], 0) + 1
    elfs = sum(1 for r in rows if r["elf"] == 1)
    arches = {}
    for r in rows:
        if r["elf"] == 1:
            arches[r["elf_machine"]] = arches.get(r["elf_machine"], 0) + 1
    distinct = len({r["sha256"] for r in rows})

    print()
    print("wrote %s" % args.out)
    print("  files read            %d" % len(rows))
    print("  distinct sha256       %d   <-- quote THIS, never the file count" % distinct)
    for k in sorted(kinds):
        print("  kind %-18s %d" % (k, kinds[k]))
    print("  ELF binaries          %d" % elfs)
    for a in sorted(arches, key=lambda x: -arches[x]):
        print("    arch %-16s %d" % (a, arches[a]))
    print("  could not be read     %d" % len(failures))
    for n, e in failures:
        print("    %s: %s" % (n, e))
    print("  read only in part     %d" % len(truncated))
    for n, s in truncated:
        print("    %s (%d bytes on disk)" % (n, s))
    if args.strings:
        print("  strings file          %s  (mode 600, DO NOT COMMIT)" % args.strings)
    print()
    print("  Nothing was executed. Nothing left this machine.")
    print()
    print("  Next: copy only the CSV back to the laptop. The files stay here.")
    print()


if __name__ == "__main__":
    main()
