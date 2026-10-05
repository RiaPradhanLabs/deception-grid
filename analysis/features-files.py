#!/usr/bin/env python3
"""
features-files.py -- static features of the captured files, computed ON THE SENSOR.

    sudo python3 features-files.py --out ~/analysis/file-features.csv
    sudo python3 features-files.py --verify          # parse, then CHECK the parse

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

    path, name, sha256, size, features_bytes, magic, kind
    ent_total, ent_w0 .. ent_w7       Shannon entropy, whole file and 8 windows
    printable_ratio, nul_ratio
    n_strings, str_mean_len, str_max_len
    elf, elf_class, elf_machine, elf_type, elf_stripped, elf_sections
    h000 .. h255                      byte-value histogram, normalised

The histogram and the entropy windows are the clustering features. Everything
before them is description.

`features_bytes` says how many bytes the features were computed over. It equals
`size` except where --max-bytes cut the read short -- two of the 136 captures on
this sensor are 30MB and 20MB, so the case is real, not hypothetical. A row built
from a prefix would otherwise be indistinguishable from one built from a whole
file, and the run summary that says so scrolls off the screen. Filter on
`features_bytes = size` before clustering if that matters.

`sha256` IS THE HASH OF THE WHOLE FILE, always. It is streamed over the entire
file even when `--max-bytes` limits how much is read for the features. An earlier
version hashed only the bytes it had read, so for any file above the limit the
column named `sha256` was the hash of a prefix -- while the run summary told you
to quote `distinct sha256` as the headline figure. A column whose meaning changes
silently for some rows is the defect this project keeps finding; here it is in
its own tooling.

VERIFY BEFORE YOU QUOTE ANYTHING. `--verify` parses the files and then checks its
own ELF reading against `file(1)`'s independent reading of the same bytes, which
is the only cross-check available on this machine without installing anything. It
reports agreement, disagreement and silence separately. A parser that quietly
produces plausible-looking numbers is the worst outcome, and this script's
sibling `features-tty.py` was exactly that until 5 October 2026.

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
        "elf_stripped": "", "elf_sections": "", "elf_truncated": "",
        "elf_no_sections": "",
    }
    # Six bytes is enough to know it is an ELF and to read its class and byte
    # order; every field past that is read through the guarded u() below and
    # comes back empty if the bytes are not there.
    #
    # This gate was 24 bytes until 5 October 2026, which silently mislabelled
    # truncated downloads as not-ELF -- and a truncated download is one of the
    # more interesting things in this collection, because it is an infection
    # that failed. Found by --verify: file(1) read one as ELF/MIPS from 20 bytes
    # while this function called it elf=0.
    if len(data) < 6 or data[:4] != b"\x7fELF":
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

    # The machines that turn up on an IoT-targeting honeypot, plus the ones a
    # cross-compiling botnet ships even when they are rare. An EM value missing
    # from this table comes out as a bare NUMBER in the CSV, which --verify now
    # reports rather than counting as "nothing to check" -- that is how m68k
    # (value 4) sat unnamed in three real samples until 5 October 2026, and
    # m68k is a standard Mirai build target.
    machines = {
        2: "sparc", 3: "x86", 4: "m68k", 5: "m88k", 8: "mips",
        10: "mipsel", 15: "parisc", 18: "sparc32plus", 20: "ppc",
        21: "ppc64", 22: "s390", 39: "mcore", 40: "arm", 41: "alpha",
        42: "sh", 43: "sparcv9", 45: "arc", 50: "ia64", 62: "x86-64",
        83: "avr", 88: "m32r", 92: "openrisc", 93: "arcompact",
        94: "xtensa", 105: "msp430", 106: "blackfin", 113: "nios2",
        140: "c6000", 183: "aarch64", 188: "tilepro", 189: "microblaze",
        191: "tilegx", 195: "arcompact2", 243: "riscv", 252: "csky",
    }
    types = {1: "rel", 2: "exec", 3: "dyn", 4: "core"}
    out["elf_machine"] = machines.get(e_machine, str(e_machine) if e_machine is not None else "?")
    out["elf_type"] = types.get(e_type, str(e_type) if e_type is not None else "?")

    # Section headers: offset and count sit at different offsets for 32/64 bit.
    if ei_class == 2:
        e_shoff, e_shnum = u(40, 8), u(60, 2)
    else:
        e_shoff, e_shnum = u(32, 4), u(48, 2)

    # A header shorter than its own stated size means the download was cut off.
    full_header = 64 if ei_class == 2 else 52
    out["elf_truncated"] = 1 if len(data) < full_header else 0

    if e_shnum is not None:
        out["elf_sections"] = e_shnum
        # Kept as its own feature, under a name that says what it measures. It
        # used to be called elf_stripped, which it is not: --verify found it
        # disagreeing with file(1) on real samples that have a section table and
        # no symbols. Both facts are useful; they are two columns now.
        out["elf_no_sections"] = 1 if (e_shnum == 0 or not e_shoff) else 0

    # Stripped means NO SYMBOL TABLE, which takes walking the section headers.
    # sh_type sits at offset 4 of every section header entry in both 32- and
    # 64-bit, so only the entry size differs.
    e_shentsize = u(58, 2) if ei_class == 2 else u(46, 2)
    if not e_shnum or not e_shoff or not e_shentsize:
        # No table at all: no symbols, so stripped.
        out["elf_stripped"] = 1 if e_shnum is not None else ""
        return out

    end = e_shoff + e_shnum * e_shentsize
    if end > len(data):
        # The table is past what was read -- truncated download, or beyond
        # --max-bytes. Unknown is recorded as unknown, never as a default.
        out["elf_stripped"] = ""
        return out

    SHT_SYMTAB = 2
    found = False
    for i in range(e_shnum):
        sh_type = u(e_shoff + i * e_shentsize + 4, 4)
        if sh_type == SHT_SYMTAB:
            found = True
            break
    out["elf_stripped"] = 0 if found else 1
    return out


def sha256_whole(path):
    """Hash the ENTIRE file, in chunks, regardless of --max-bytes.

    Separate from the feature read on purpose: the features are allowed to look
    at a prefix of a very large file, but the identity of the file is not.
    """
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


# `file -b` prints things like:
#   ELF 32-bit LSB executable, MIPS, MIPS-I version 1 (SYSV), statically linked
# so its words can be checked against what elf_header() read out of the bytes.
MAGIC_CLASS = re.compile(r"ELF\s+(32|64)-bit", re.I)
# Only wordings that have actually been seen from file(1) go in here. A guessed
# wording would turn a silence into a false mismatch, which is worse: silence is
# reported as silence, and a mismatch would send someone hunting a bug that is
# not there.
MAGIC_ARCH = {
    "motorola m68k": "m68k", "m68k": "m68k",
    "mips": "mips", "intel 80386": "x86", "x86-64": "x86-64",
    "arm aarch64": "aarch64", "aarch64": "aarch64", "arm": "arm",
    "sparc": "sparc", "powerpc": "ppc", "renesas sh": "sh",
    "ucb risc-v": "riscv", "risc-v": "riscv",
}


def magic_says(magic):
    """What file(1) thinks the class, architecture and stripping are, or None.

    None means file(1) did not say, which is different from disagreeing and is
    counted separately.
    """
    cls = None
    m = MAGIC_CLASS.search(magic or "")
    if m:
        cls = m.group(1)
    low = (magic or "").lower()
    arch = None
    # Longest key first, so 'arm aarch64' wins over 'arm'.
    for key in sorted(MAGIC_ARCH, key=len, reverse=True):
        if key in low:
            arch = MAGIC_ARCH[key]
            break
    # Order matters: 'not stripped' contains 'stripped'.
    if "not stripped" in low:
        stripped = 0
    elif "stripped" in low:
        stripped = 1
    elif "no section header" in low:
        stripped = 1
    else:
        stripped = None
    return cls, arch, stripped


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


def verify(names, directory, max_bytes):
    """Check this script's ELF reading against file(1)'s, on the real files.

    Two independent readings of the same bytes. file(1) has its own magic
    database and knows nothing about elf_header() below; where they agree, the
    header offsets are right. Where they disagree, one of them is wrong and the
    numbers must not be used until it is known which.

    Reads only. Executes nothing, writes nothing, sends nothing.
    """
    agree = disagree = quiet = 0
    mismatches = []
    checked = []
    # Per field, so a field nobody checked cannot hide inside an overall pass.
    # The first version of this function compared class and architecture only
    # and reported DISAGREED 0 while the stripped flag was wrong on real
    # samples. A check that is silent about a column is not a check of it.
    per_field = {"class": [0, 0, 0], "machine": [0, 0, 0], "stripped": [0, 0, 0]}
    # An EM value this script has no name for. Counted on its own, because it is
    # not a disagreement and it is not nothing: the CSV would carry a number
    # where every other row carries a name.
    unnamed = {}
    # An architecture file(1) named that MAGIC_ARCH cannot map, so the field
    # could not be checked for that file at all.
    unmapped = {}

    def tally(field, ours, theirs):
        """[agreed, disagreed, file(1) said nothing]"""
        if theirs is None or ours == "":
            per_field[field][2] += 1
            return True
        if str(ours) == str(theirs):
            per_field[field][0] += 1
            return True
        per_field[field][1] += 1
        return False

    for name in names:
        path = os.path.join(directory, name)
        try:
            with open(path, "rb") as fh:
                data = fh.read(max_bytes)
        except Exception as exc:
            print("  could not read %s: %s" % (name[:16], exc))
            continue
        parsed = elf_header(data)
        magic = file_magic(path)
        m_cls, m_arch, m_strip = magic_says(magic)

        if not parsed["elf"]:
            # Not an ELF by our reading. If file(1) calls it one, that is a
            # disagreement and matters more than the agreeing cases.
            if m_cls or "ELF" in (magic or ""):
                disagree += 1
                mismatches.append((name, "we say not ELF", magic))
            else:
                quiet += 1
            continue

        if str(parsed["elf_machine"]).isdigit():
            unnamed[str(parsed["elf_machine"])] = unnamed.get(
                str(parsed["elf_machine"]), 0) + 1
        if m_arch is None and parsed["elf"]:
            # Pull the phrase after the class, which is where file(1) puts the
            # architecture, purely so the report can name what it could not map.
            bit = (magic or "").split(",")
            word = bit[1].strip()[:40] if len(bit) > 1 else (magic or "")[:40]
            unmapped[word] = unmapped.get(word, 0) + 1

        ok_cls = tally("class", parsed["elf_class"], m_cls)
        ok_arch = tally("machine", parsed["elf_machine"], m_arch)
        ok_strip = tally("stripped", parsed["elf_stripped"], m_strip)

        if m_cls is None and m_arch is None and m_strip is None:
            quiet += 1
        elif ok_cls and ok_arch and ok_strip:
            agree += 1
        else:
            disagree += 1
            bad = [f for f, ok in (("class", ok_cls), ("machine", ok_arch),
                                   ("stripped", ok_strip)) if not ok]
            mismatches.append((name,
                               "ours: %s-bit %s stripped=%s  [%s]"
                               % (parsed["elf_class"], parsed["elf_machine"],
                                  parsed["elf_stripped"], ", ".join(bad)),
                               magic))
        checked.append((name, parsed, magic))

    print()
    print("ELF header cross-check against file(1)")
    print("  agreed                %d" % agree)
    print("  DISAGREED             %d" % disagree)
    print("  file(1) said nothing  %d   (not an ELF by either reading, or nothing named)"
          % quiet)
    print()
    print("  per field: agreed / DISAGREED / file(1) silent")
    for f in ("class", "machine", "stripped"):
        a, d, q = per_field[f]
        print("    %-9s %5d / %5d / %5d%s" % (f, a, d, q,
                                              "   <-- UNCHECKED" if a == 0 and d == 0 else ""))
    print()
    for name, ours, magic in mismatches:
        print("  MISMATCH %s" % name[:24])
        print("    %s" % ours)
        print("    file(1): %s" % magic[:120])
    if unnamed:
        print("  EM VALUES THIS SCRIPT HAS NO NAME FOR -- the CSV would carry a number:")
        for v in sorted(unnamed, key=lambda x: -unnamed[x]):
            print("    machine=%s  x%d   <-- add it to the machines table" % (v, unnamed[v]))
        print()
    if unmapped:
        print("  architectures file(1) named that MAGIC_ARCH could not map,")
        print("  so the machine field was NOT checked on those files:")
        for w in sorted(unmapped, key=lambda x: -unmapped[x]):
            print("    %-42s x%d" % (w, unmapped[w]))
        print()
    print()
    print("  a few parses in full, for reading by eye:")
    for name, p, magic in checked[:6]:
        print("    %s" % name[:24])
        print("      ours    class=%s machine=%s type=%s sections=%s stripped=%s "
              "no_sections=%s truncated=%s"
              % (p["elf_class"], p["elf_machine"], p["elf_type"],
                 p["elf_sections"], p["elf_stripped"], p["elf_no_sections"],
                 p["elf_truncated"]))
        print("      file(1) %s" % magic[:110])
    print()
    if disagree:
        print("  DO NOT USE THE CSV. Two readings of the same bytes disagree.")
        print()
        return 1
    if unnamed:
        print("  The parse agrees with file(1) everywhere it was checked, but the")
        print("  machines table is missing %d EM value(s). Add them before the CSV"
              % len(unnamed))
        print("  is used, or those rows carry a number where the rest carry a name.")
        print()
        return 1
    unchecked = [f for f in per_field if per_field[f][0] == 0 and per_field[f][1] == 0]
    if unchecked:
        print("  NOT CROSS-CHECKED AT ALL: %s." % ", ".join(unchecked))
        print("  file(1) said nothing about those fields on any file, so this run")
        print("  proves nothing about them. Do not treat them as verified.")
        print()
        return 1
    print("  Nothing was executed. Nothing left this machine.")
    print()
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dir", default=DEFAULT_DIR, help="directory of captured files")
    ap.add_argument("--out", default=None, help="CSV to write")
    ap.add_argument("--verify", action="store_true",
                    help="parse the files and check the ELF reading against "
                         "file(1), without writing a CSV")
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

    all_names = sorted(n for n in os.listdir(args.dir)
                       if os.path.isfile(os.path.join(args.dir, n)))
    # Cowrie keeps a .gitignore in its downloads directory. A dotfile is
    # housekeeping, not a captured sample, and counting one as a sample inflates
    # the figure the summary tells you to quote. Skipped BY NAME rather than by
    # a glob that would omit it without saying so.
    skipped = [n for n in all_names if n.startswith(".")]
    names = [n for n in all_names if not n.startswith(".")]
    if skipped:
        print("not samples, skipped: %s" % ", ".join(skipped))
    if not names:
        sys.exit("NOTHING MATCHED in %s -- refusing to write an empty CSV.\n"
                 "An empty result here looks exactly like a successful run, "
                 "which is the whole problem." % args.dir)

    if args.verify:
        sys.exit(verify(names, args.dir, args.max_bytes))

    if not args.out:
        sys.exit("--out is required unless you pass --verify")

    cols = (["path", "name", "sha256", "size", "features_bytes", "magic", "kind",
             "ent_total"]
            + ["ent_w%d" % i for i in range(WINDOWS)]
            + ["printable_ratio", "nul_ratio",
               "n_strings", "str_mean_len", "str_max_len",
               "elf", "elf_class", "elf_machine", "elf_type",
               "elf_stripped", "elf_sections", "elf_truncated",
               "elf_no_sections"]
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
            "sha256": sha256_whole(path),
            "size": size,
            # How many bytes the FEATURES below were computed over. Equal to
            # `size` for almost every file; smaller when --max-bytes cut the
            # read short. Without this column a row built from a 16MB prefix is
            # indistinguishable from one built from a whole file, and the run
            # summary saying so scrolls away. `sha256` is always the whole file.
            "features_bytes": len(data),
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
    cut = sum(1 for r in rows if r.get("elf_truncated") == 1)
    print("    of those, truncated %d   <-- an infection that failed to download"
          % cut)
    for a in sorted(arches, key=lambda x: -arches[x]):
        print("    arch %-16s %d" % (a, arches[a]))
    print("  could not be read     %d" % len(failures))
    for n, e in failures:
        print("    %s: %s" % (n, e))
    print("  read only in part     %d   <-- features from a prefix; see features_bytes"
          % len(truncated))
    for n, s in truncated:
        print("    %s" % n)
        print("      %d bytes on disk, features over the first %d"
              % (s, args.max_bytes))
    if args.strings:
        print("  strings file          %s  (mode 600, DO NOT COMMIT)" % args.strings)
    print()
    print("  Nothing was executed. Nothing left this machine.")
    print()
    print("  Next: copy only the CSV back to the laptop. The files stay here.")
    print()


if __name__ == "__main__":
    main()
