# Lessons learnt, and what I would do differently

Deception Grid — ReDI School cybersecurity capstone.
Written 30 September 2026, five days into collection, with the build finished and
the OT door due to open on 6 October.

This document exists because the corrections in this project turned out to be
worth more than the findings. Eight substantive mistakes were made and fixed in
the first five days. Every one is recorded in `docs/build.md` and
`docs/rules-of-engagement.md` alongside the figures it produced, and the originals
were kept rather than replaced.

What follows is the part that transfers to the next project.

---

## The one rule

> **Before quoting a count, look at five of the rows it counts.**

Of the eight mistakes below, **six were found by reading rows and none by reading
totals.** Three were found only because a tool printed what it had discarded
without being asked to.

The reason is structural rather than a matter of care: a total is a summary of
evidence, and a summary is the one thing that cannot show you it is wrong. A
wrong total looks exactly like a right one. This is the same failure as a control
marked compliant because nobody opened the sample, or a dashboard that is green
because the query behind it silently returns nothing.

---

## What went wrong, in one table

Kept short deliberately. The full account of each is in `docs/build.md`.

| | What happened | How it was found | Cost |
|---|---|---|---|
| 1 | The log rotates daily and we read one file of five. Every figure for a week came from the current day's file | Noticed a filename with a date in it | 14,845 events became 201,234; 93 sources became 967 |
| 2 | Event counts published as "arrivals" | Comparing two figures that should have matched | ~5× overstatement |
| 3 | Five figures wrong in one morning — 259 downloads, 331 connections, 104 samples, 112 sessions, "no payload was delivered" | A tool that prints what it counted | A published correction, then an error inside the correction |
| 4 | The exclusion rule was wrong in five successive versions | Reading the excluded rows, every time | A day of rework |
| 5 | Fixing the rule changed nothing already stored. Then the fix for that fixed one column of twelve | Seeing a row in the excluded list that the current rule would have allowed | Two rounds of the same bug |
| 6 | The sensor made 153 outbound connections to attacker machines over four days, against a written rule saying it never would | Reading the logs properly for the first time | Four days of policy violation |
| 7 | The firewall rule that fixed it named one account. The second decoy ran unprotected for four hours | Checking uids while extending the rule | Four hours |
| 8 | We published the sensor's own address in a public repository | Checking the *repository*, having already checked our working files | A few hours of exposure, permanent in history |

Plus a category of its own: **six defects in the OT honeypot's shipped example
template**, including event recording disabled by default with an unwritable
path — which would have produced a decoy that answered every question correctly
and recorded nothing.

---

## Lessons

### On measurement

**A total cannot tell you it is wrong.** See the rule above. This is the single
most valuable thing the project produced and it cost five wrong figures to learn.

**Measure the thing, not a proxy for it.** Two examples, both of which failed.
Watching for the outbound block failing by counting files in a folder raised a
false alarm within the hour — that folder also fills with files attackers push,
which keep arriving whether or not the firewall works. And 108 files on disk
against 67 distinct files by content: the file count is not a count of samples,
because captured shell redirections are named by a random identifier rather than
by content.

**Reading a rule tells you intent. Counting the thing it prevents tells you it
works.** The monitoring does both, and the second is the one that matters.

**Timestamp every figure at the point of generation.** These numbers grow while
the sensor runs. An earlier snapshot is not wrong, it is earlier — but only if
the snapshot carries its date. Two of the "corrections" turned out to be nothing
more than stale figures being compared to fresh ones.

**Never work from a truncated view.** One wrong claim — "no payload was ever
delivered" — came from reading a command list that had been cut off at fifteen
rows. The list was not lying; the reader was not looking at all of it.

### On tools

**A tool should print what it discarded, and what it read, on every run,
unqualified.** This one habit caught three of the eight mistakes. In one case the
output was *"excluded: none"*, which is how we learned a rule was matching
nothing at all.

**A derived value is only as current as the last time it was derived.** Every
column except the original log line is computed. Change the code that computes it
and nothing already stored changes — silently, indefinitely. The pipeline now
recalculates every derived field from the original line on every run, and prints
what moved. It is idempotent, which is how we know it works: run it twice and the
second run says *nothing changed*.

**Build the counting tool before writing any findings.** Every wrong figure in
this project was produced by hand-counting before the pipeline existed. This is
the single change with the largest payoff.

**Test against observed data, not imagined data — and do not filter against
imagined patterns either.** These pull in opposite directions and both are right.
The regression suite is sixteen cases as of 5 October (nineteen when this was
written; it now lives inside `ingest.py --selftest`), every one either a row
seen on this sensor or a specific defect a previous version had; it caught a bug that had
already been fixed once and was reintroduced by its own fix. But when a rule was
written for a pattern nobody had observed, the reasoning to leave it alone was
also correct — and then the pattern appeared in the real data within the hour.
The resolution: write the check, do not write the filter, and let the data decide.

### On controls

**Enforce at the layer that cannot be quietly undone.** A configuration setting
covers the commands somebody thought of, survives until the next upgrade, and is
trusted rather than checked. A packet filter covers every command including ones
not yet written. *A setting is a statement of intent; a firewall rule is a fact.*

**A control written against an instance is not a policy.** The outbound rule named
one user account, so it protected one process. "The decoys never reach out" is the
policy; that account was one instance of enforcing it. A third decoy would need
the same line and nothing would have reminded anyone.

**A control you switch off when it is inconvenient is not a control.** The rule
later blocked our own deployment method. The fix was to change the deployment, not
to lift the rule for a minute.

**Prefer loud failure to silent success.** The expensive failures were not the ones
that stopped work — a hung file copy is obvious. They were a paste that dropped
four characters from the middle of a file, an edit that ran in the wrong directory
and reported success, and a guard that could not read the file it was guarding so
the guarded command ran anyway. All three produced something that looked like a
working result.

**Verify out of band.** When the machine's identity appeared to have changed, the
answer was never "delete the stored key and reconnect" — cloud providers reassign
addresses, and that warning can mean a stranger's server is answering. Three
commands through the provider's management interface settled it: is the address
still ours, is the machine running, what are its real fingerprints and when were
they created.

### On documentation

**Check what you published, not what you hold.** A privacy sweep over the working
files came back clean, which was true and beside the point: the repository had
already been committed one revision earlier. The check now covers every path the
repository has *ever* held, not every path it holds now.

**Knowledge encoded in a script is not documentation.** The correct SSH port had
been sitting in an automation script for days, working perfectly. It was absent
from the prose, so a human with nothing to copy reached for the obvious command
and walked into the honeypot. The script cannot be wrong about the port — which is
exactly why nobody noticed the port was undocumented.

**Never delete an apparent duplicate without asking what is in it that is nowhere
else.** Two findings documents existed in near-duplicate. Everything said the
shorter, older one with a typo in it was safe to delete. The only content unique
to it was an unexamined lead — the easiest kind of thing to lose in a rewrite,
because nobody misses what they did not know was there.

**Keep the wrong versions.** A project that quietly replaces its numbers has
thrown away the only evidence that it checks its work.

### On the honeypots themselves

**Defaults are built for testing the software, not for collecting data.** The OT
honeypot's shipped example introduced itself by the honeypot product's own brand
name, answered at addresses taken from equipment manuals rather than the ones the
protocol actually uses, held values that were all zero and never changed, made an
outbound call on startup, listened on a test port, and had event recording
disabled by default pointing at an unwritable path. An out-of-the-box honeypot is
a decoy of a honeypot.

**Test from the outside before opening the door.** Every one of those defects was
visible on the wire. They were found by sending raw protocol frames over a plain
socket rather than using a convenient client library, so the results describe the
wire rather than somebody's library.

**A decoy that is obviously dead teaches you nothing, and one that is obviously
noisy teaches you nothing either.** Values all zero are fake; values re-rolled at
random on every request are fake at the next level up, because no plant flips every
valve every three seconds. The readings are functions of the clock, they agree with
each other, and the counters start from a plausible commissioning date.

**Design the comparison, not just the instrument.** Two decoys on one machine, one
address, means the only difference between the two doors is the door. Same country,
same moment, same scanners sweeping past. Two machines would have confounded it.

---

## What I would do differently

Ordered by how much each would have saved.

**1. Build the ingest pipeline on day one, before writing a single finding.**
Every wrong figure came from hand-counting before the tool existed. The tool took
an afternoon; the corrections took a week.

**2. Check how every tool rotates its logs, before quoting any total.** One
directory listing would have prevented the largest error in the project. Anything
reading a log reads `name*`, not `name`, from the first line of code.

**3. Put the outbound block in before going live.** It was always the stated
policy. It is two lines of firewall configuration. Instead it went in after four
days of violating the document that stated it.

**4. Write controls against the policy, not the process.** A group rather than a
single user account, so that adding a second decoy inherits the protection instead
of quietly falling outside it.

**5. Run the secret-scan over the repository's full history from the first
commit**, not over the working directory. And run it *before* each commit rather
than after somebody wonders.

**6. Write down how to connect to the machine, on the day the machine exists.**
Including the port, and why it is not the obvious one.

**7. Decide the as-of discipline before writing any findings note.** Every figure
carries a timestamp, in the same format, from the beginning — rather than being
retrofitted across seven documents.

**8. Make every script print its inputs and its exclusions from version one.**
It is four lines and it caught three mistakes.

**9. Build the regression fixture early, from real observed rows.** The
test cases (nineteen then, sixteen now, inside `ingest.py --selftest`) exist
because a rule went wrong five times. Two of those five would
have been caught on the first run.

**10. Use a checksummed or encoded transfer for any file over about fifty lines,
from the start.** Two hours went into diagnosing corruption that a decoding step
would have refused outright.

**11. Test the honeypot from the outside before opening the firewall**, as a
standing step rather than a good idea somebody had late.

**12. Create the reminder at the moment the dependency appears.** Three dated
commitments existed in conversation for hours before any of them was scheduled,
and one was nearly lost.

**13. Keep one canonical copy of every document.** Two near-duplicates of the same
findings note existed because an upload created a second file rather than
replacing the first, and nobody checked.

---

## What I would keep, unchanged

- **Exclusions labelled, never deleted.** Every excluded row stays in the
  database, countable and arguable. The exclusion tally is quoted alongside every
  figure.
- **The original log line kept on every row.** It is the only authority; everything
  else is a cache of what the current code makes of it.
- **One facts table for both decoys.** Two would have made every cross-door
  question a join and given the exclusion rules two places to disagree.
- **Corrections published beside the originals**, with their windows.
- **Refusing to guess.** Several times the right move was to read the source or run
  one command rather than write a plausible-looking import path. The times that
  discipline slipped are three of the eight mistakes.
- **"Only ever receive"** as the project's one hard rule — and treating each
  violation of it as a finding rather than an embarrassment.
- **Never executing a captured sample, and never copying one off the machine.**

---

## What I still do not know

Stated as open questions, because a report that pretends to have finished is less
useful than one that says where it stopped.

1. **Whether the OT door attracts different visitors from the IT door.** This is
   the question the project was built to answer. The OT door opens 6 October and
   will have about 66 days of exposure against the IT door's 77 by demo day —
   close enough to compare, provided both dates are stated.
2. **Whether the three sources that tried to use us as a relay are the same
   person.** A client fingerprint was recorded for each, and it survives a change
   of address. Comparing them is one query nobody has run.
3. **About six login records out of 34,000 that cannot be classified.** They
   survive the filter and still look like keyboard noise. Left visible in a
   standing query rather than answered with a sixth version of the rule.
4. **Whether the visitors who got all the way in behave differently from the ones
   that only knocked.** The most interesting question available and the least
   started.

---

## How to talk about this

The temptation with a project like this is to lead with the traffic. The traffic
is not the interesting part — every internet-facing machine gets it.

What is defensible in front of an examiner, an interviewer or an auditor is this:
**a rules document that has been violated twice by the project it governs, with
both windows recorded, both causes diagnosed, and both fixed at a layer that does
not depend on anyone remembering.** A rules document that has never been violated
is usually one nobody has audited.

The second thing worth leading with: **being wrong in both directions.** Of the
figures corrected, most were overstated and one was understated. That matters,
because a set of corrections that all happen to make the project look better is
not a set of corrections.

---

*Figures in this document are as at 29 September 2026, 17:25 UTC. The verified
headline set: 1,030 distinct sources, 34,427 password attempts, 285 sources that
got all the way in, 153 outbound connections in the four days before they were
blocked, 67 distinct captured files, and 18 attempts to use the machine as a
relay — every one refused.*


---

# Addendum — 5 October 2026

Added the day before the OT door opened. The body of this document is as at
29 September 2026, 17:25 UTC and is unchanged; this section records what one
further working session added, in the same sections, so the original's as-at
date stays meaningful.

Three of the four mistakes in this session were found the same way as the
original eight — by looking at the rows rather than the totals, or at the
directory rather than the file.

## Addition to the one rule

The rule holds, with a sibling that cost two documents and a wrong procedure:

> **Before acting on a procedure, list the repository.**

A `ufw` command for opening the OT door was worked out from first principles
while `docs/opening-the-ot-door.md` sat in the repository unread. The derived
command was half the procedure — ufw without the NSG — which that runbook
itself warns produces a door that looks open and is not. In the same session
two documents were written before noticing one of them already existed. One
`git ls-files` would have prevented all of it.

The structural reason is the same as the one above. A file you have not listed
looks exactly like a file that does not exist.

## On tools

**A warning is not harmless until you trace what reads its exit status.**
`tar: file changed as we read it` is genuinely benign for the archive — the next
tarball carries the file complete — and it was dismissed as cosmetic twice, once
in writing. It was not benign for the script. GNU tar exits **1** on that
warning, and the remote command was `sudo tar ... && sudo chown ...`. Exit 1
short-circuited the `&&`, so the `chown` never ran, the archive stayed
root-owned, and `/tmp`'s sticky bit then refused the cleanup `rm`. A
cosmetic-looking exit code disabled a step two lines later. Classify a warning
by what reads its exit status, not by what it says about the data: any
`command-that-warns && cleanup` is this defect waiting for a warning to occur.

This belongs beside *prefer loud failure to silent success*, and the mechanism
is worth distinguishing — here the failure was announced on stdout and still
invisible, because the thing that broke was two lines away from the thing that
printed.

**When the failing condition is not yours to summon, construct it in isolation.**
The replacement guard had to tolerate tar's exit 1 and throw on exit 2. A live
run demonstrated only the first half, and only by luck, because tar exited 0
that time. Rather than wait for the warning to recur, the assumption underneath
the guard was tested directly: `ssh host 'exit 1'` and `ssh host 'exit 2'`
returned 1 and 2. That proved both branches and the load-bearing premise that
ssh propagates remote exit codes at all — had it swallowed them, the guard could
never have fired and would have looked like it worked. This extends *test
against observed data*, which is about inputs, to the case where the trigger is
external.

**A byte-count delta proves an edit was surgical.** After a one-line change the
file went 4,499 → 4,517 bytes: exactly the 18-byte difference between the old
line and the new one. One number established that no editor had added a
byte-order mark and that nothing else had moved. Worth doing after any edit made
in a tool that might reformat, re-encode or re-line-end a file it was asked to
change one line of.

## On controls

**Unlink permission depends on the directory, not the file.** The obvious
repairs to the cleanup failure above were to change `&&` to `;`, or to tolerate
exit 1 before chowning. Both would have left the cleanup depending on a `chown`
succeeding. Staging the archive in a directory the ssh user owns, at mode
`0700`, made deletion independent of who `tar` ran as — the fragile link stopped
mattering rather than being patched, and the `0700` removed an exposure as a
side effect. In the spirit of *enforce at the layer that cannot be quietly
undone*: when a fix must keep working unattended for two months, prefer the
change that deletes the failure mode to the change that handles it. Ask what the
operation actually depends on; it is often not what the code appears to be
managing.

**The exposure mattered more than the leftover.** The uncleaned archive was mode
644 in a world-readable directory **on the honeypot itself** — a complete copy
of the collection readable by any local account on the one machine deliberately
exposed to the internet. Cowrie is medium-interaction so no attacker gets a real
shell and the practical risk was low, but the exposure was unnecessary and
unseen. It was also **intermittent**, firing only when an attacker happened to
be active during the archive window: two runs in five that morning, and one
orphan in ten days of uptime. A fault conditional on external timing will not
appear in testing and will appear in the data. Reason about the mechanism rather
than trying to reproduce it.

## On the honeypots themselves

**Configured is not proven.** This document already records that the OT
honeypot shipped with event recording disabled and pointing at an unwritable
path, and that it was fixed. What remained unverified until 5 October is that
the corrected configuration had ever written anything: `conpot.json` held
**zero records**, so the write path had never once run.

One loopback Modbus frame — an ordinary read-holding-registers request, function
3, unit 1, one register — produced three records and proved the whole chain. The
reply decoded as function `03` rather than `83`, so no exception; the record
carried `sensorid decoy-01-ot`, `dst_port 502`, the function code, and
`public_ip: null`, confirming that `fetch_public_ip = False` really does leave
it empty. It also rendered a `last event` line in `decoy-status` that had never
executed, because there had never been a record to show.

Before a collection window opens, exercise the collection path end to end with
synthetic input you can identify and exclude afterwards. *Test from the outside
before opening the door* covers the wire; this covers the record. Fixing a
default is not the same evidence as watching it work.

## On documentation

**Artefact filenames need the zone discipline already applied to figures.**
*Timestamp every figure at the point of generation* is in this document and is
about figures. The same applies to artefact names, for a harder reason. Tarball
names were local Austrian time while every timestamp inside them was UTC — a
two-hour gap between a file's label and its contents. The forcing reason was not
tidiness: Austria returns to CET on **25 October 2026**, inside the collection
window, which would produce an hour that occurs twice and two distinct archives
competing for one name.

Two things mattered more than the rename. The laptop and sensor clocks were
checked to agree in UTC first, because an offset clock would have produced names
that were confidently wrong rather than consistently shifted. And `ingest.py`
was checked for filename parsing before anything changed — it derives dates only
from record contents, so the changeover could not reach the dataset. Pick UTC,
mark it in the name, keep the authoritative timestamp inside the record, and
before changing a naming scheme find everything that parses the name.

Filenames from `decoy-2026-10-05-0346Z.tar.gz` onward are UTC with a `Z`
suffix. Earlier names were deliberately not changed, by *keep the wrong
versions*; the boundary is recorded rather than erased.

## Additions to *what I would do differently*

**Read the repository's file list before acting on any procedure.** See the
addition to the one rule above.

**Make the exclusion list a function of the policy, not a list of instances.**
This is *a control written against an instance is not a policy*, applied to data
rather than to firewalls. `exclude-ips.txt` names specific addresses while the
residential address rotates daily, so the list cannot keep pace by hand — and
`allow-me.ps1` already learns each new address without recording it anywhere.
Separately, excluding a bare address *permanently* over-excludes: a residential
IP that was ours in September may be reassigned to someone whose scan is genuine
data. Address-plus-date-range is the defensible form.

## Additions to *what I still do not know*

**Whether the IPv4-only bound limits the comparison more than expected.** Both
decoys bind `0.0.0.0` — verified 5 October by `ss -lntp` — so the v6 ufw rules
on 22, 23 and 502 are inert and no IPv6 scanner reaches either door. This was a
candidate confound and turns out not to be one, which is the good outcome: both
doors face the same internet, and the limitation is symmetric. But it bounds the
population, and by how much is unknown.

**Whether Conpot's listen backlog of 100 has ever refused a connection.** Cowrie
and sshd use 4096. Probably ample at Modbus scan rates, but a burst beyond it
means refused connections, and a refused connection is data never recorded.
Unmeasured, and it will not announce itself.

## Two corrections owed to other documents in this repository

**`docs/opening-the-ot-door.md`, closing section** — *"`exclude-ips.txt` already
holds your addresses."* It does not hold the current one, and the address
rotates daily. Steps 5 and 6 assume `ingest.py` filters the analyst's own test
connection through that file; it will not, and the day-one OT dataset would
record the analyst as a genuine external source. The address `allow-me.ps1`
reports must be appended to `exclude-ips.txt` before step 5, and `ingest.py`
re-run. **Still outstanding at the time of writing.**

**`config/conpot.cfg`, the `fetch_public_ip` comment** — stated that the
29 September outbound reject rule covered uid 1001 only, and reasoned from there
that the setting was the only thing preventing an outbound connection. Both uids
are rejected in `ufw-before-output`, verified against the packet filter, and
that chain is evaluated ahead of ufw's user rules so a later `ufw allow out`
cannot override it. **Corrected** in commit `f84e6ec`, as an insert above the
original paragraph rather than a rewrite of it, leaving the earlier reasoning
visible.

Both are instances of a lesson already in this document — *reading a rule tells
you intent, counting the thing it prevents tells you it works* — found in our
own documents rather than in a vendor's.

---

*Addendum figures are as at 5 October 2026, 05:40 UTC: 455,524 Cowrie events
across 11 rotated log files, 2,183 distinct sources, 136 captured files, 132 TTY
recordings, and 3 OT records, all three from the loopback probe described above.
Event arrival rate over that morning varied from roughly 29 to 79 per minute,
nearly threefold within four hours, which is worth stating rather than averaging.
`ingest.py` remains the figure to quote.*

---

# Addendum — 5 October 2026, afternoon

The morning addendum above was written at 05:40 UTC. This one covers the rest of
the day: the TTY parser, the artefact rule, and one planned analysis abandoned on
measurement. Appended rather than woven in, for the same reason as before — the
as-at dates above stay meaningful.

## Addition to the one rule

The rule at the top of this document is *before quoting a count, look at five of
the rows it counts*. It guards against trusting a summary. This morning's
addendum added its mirror image: *when a thing moves, go and look at everything
that names it*.

Today adds a third, and it is the subtlest of them:

> **A tool can quietly narrow its own input, and a total computed over a
> silently filtered set looks exactly like a total.**

Three census scripts were written against the TTY recordings using
`glob.glob(dir + '/*')`. Python's `glob` does not match files beginning with a
dot, and Cowrie keeps a `.gitignore` in that directory. Every one of those runs
silently excluded a file and reported a clean, confident total. The rewritten
tool uses `listdir`, found the file, and now prints what it skips **by name**:

```
not recordings, skipped: .gitignore
```

The count of real recordings was never affected. That is exactly why it matters:
nothing in the output was wrong, and nothing would ever have said so. The first
rule asks whether a number is true. This one asks whether the number was
computed over the set you think it was.

## On measurement

**A measurement can retire a planned analysis, and that is a result rather than
a gap.** The TTY recordings were collected partly to support keystroke-timing
analysis — separating a human at a prompt from a pasted script by the rhythm of
the characters. Measured across all 130 recordings:

| | |
|---|---|
| Input records from visitors | 593, totalling 67,669 bytes |
| Mean bytes per input record | 114.1 |
| Records ending in CR or LF | 373 |
| Records carrying exactly one character | 5 — `e`, `x`, `i`, `t`, `w` |
| Records containing a backspace | 1 |
| Recordings that are a single pasted command | 62 of 130 |

A keystroke is one byte. Cowrie writes one record per chunk arriving on the
wire, so a 114-byte record is a whole command line pasted or piped in. The only
characters ever delivered one at a time in this dataset spell `exit`, plus a
single `w`. One machine on the open internet for ten days is reached almost
entirely by automation, and automation does not type.

So the analysis was withdrawn. Writing that down is worth more than quietly
dropping it: a published technique could not be applied here, the reason is a
property of the traffic rather than of the tooling, and no amount of further
collection changes it. The replacement is smaller and honest — intervals between
*commands*, 464 of them across the 20 recordings with ten or more commands,
reported as descriptive statistics and named `icg` so they can never later be
quoted as keystroke intervals.

**Predict the change before you make it.** Before the artefact rule was
deployed, a read-only script ran the old and new rules side by side over the
stored rows and predicted that 22 attempts would be reclassified. The
re-derivation moved 22. A re-derive whose output you cannot state in advance is
not a verification of anything; it is a hope that the number looks reasonable
afterwards.

## On tools

**An undocumented binary format should be read, not recalled.** The TTY parser
assumed a header layout from recollection of Cowrie's source and was wrong in
two independent ways within 24 bytes — the field order, and the op constants.
The fix came from dumping the first 64 bytes of a real recording and finding
where the Unix timestamp actually landed:

```
offset  0  op         1 = open, 2 = close, 3 = write
offset  4  unused     always 0 in every record observed
offset  8  length     payload bytes following the header
offset 12  direction  1 = input, 2 = output, 3 = interact
offset 16  sec        Unix seconds
offset 20  usec       microseconds
```

The proof the layout is right is structural rather than plausible: all 130
recordings walk to their exact end with zero trailing bytes, and each yields
exactly one open record and one close record. A wrong field order desynchronises
within a handful of records, so reaching the final byte 130 times is evidence.

**A tool that cannot fail loudly will fail quietly.** The broken parser was
caught only because its `--verify` mode refused to produce output it could not
justify, printing `length=1790661295 is not plausible` instead of a plausible
number. Two further guards were added on the same reasoning: a parse failure now
exits non-zero so a scheduled run cannot read it as success, and recordings with
no measurable interval are kept as rows rather than dropped — 62 of 130 are a
single pasted command, and that proportion is itself the finding.

**A rule can be correct and still not be in force.** Version six of the artefact
rule was written, documented and passing its own self-test — on the laptop. The
sensor was still running version five, and the database still held version-five
verdicts, because every column except `raw` is derived and `INSERT OR IGNORE`
never revisits a row it already holds. Three places had to agree before the
change existed anywhere that mattered: the repository, the sensor, and the
re-derived rows.

The self-test is what prevented the same rule being written twice. Running
`ingest.py --selftest` as the first step, rather than reading the code and
assuming, showed all 16 cases already passing.

## On controls

**A diagnostic that prints nothing is ambiguous, and the ambiguity has to be
resolved before it is relied on.** `ingest.py` prints a `window checks N inside,
N outside, N undated` line so that a date-scoped exclusion doing nothing cannot
go unnoticed. After today's run the line was absent entirely. That has two
possible meanings — the windows were bypassed, or they were never reached — and
only one is benign.

It was the benign one, confirmed by query: zero rows in the database carry the
laptop's address, because admin SSH is on port 62222 where real `sshd` handles
it and Cowrie never sees it, and the Modbus probe ran from the machine itself.
The counters are truthfully zero. But the mechanism is therefore **unexercised
in production**, and the first event that will ever carry a windowed address is
step 5 of the OT-door runbook, which connects to port 502 from the laptop.

The lesson is that *absent* and *zero* are different outputs and should look
different. A counter that prints nothing when it has counted nothing cannot be
distinguished from a counter that was never called.

**A self-identifying test credential makes your own traffic self-documenting.**
The 15 rows excluded as the analyst's belong to two addresses that are in
`exclude-ips.txt` without dates, so they are excluded for all time — the
over-exclusion risk this project built windows to avoid. Checking whether that
was right took one query, and the answer was certain rather than probable only
because one row reads:

```
cowrie.login.failed   'root' / 'no-honey-in-this-pot'
```

Nobody else sends that. A dated line in `analyst-addresses.log` records which
address was ours; a credential like that records it *inside the data*, where it
survives every later question about whether the exclusion list was correct. Do
it deliberately from now on, including on the OT side — a register write with a
recognisable value does the same job on Modbus.

## A reported success, one more time, in the tooling itself

The one rule found a new place to apply on the same afternoon, and this time in
the mechanism used to move files onto the laptop rather than in the project's own
code.

Two files were written to the laptop's checkout. The write reported
`"written"`, with nothing rejected, and the files' modification times on disk
changed to match. Both checks said the delivery had worked. Then:

```
features-files.py   19,140 bytes written   11,227 bytes on disk
analysis/README.md   9,899 bytes written    6,111 bytes on disk
```

The content that arrived was a stale copy of each file from earlier in the day.
It was not noticed from the report, which was clean, nor from the timestamps,
which moved. It was noticed because the next step copied one of the files to the
sensor and the transfer printed `11KB` where `19KB` was expected — and then
confirmed because the hash the sensor computed matched the stale copy exactly.

Two files delivered the same way minutes earlier arrived intact, so the failure
is intermittent and no explanation for it is offered here. What follows from it
does not depend on knowing the cause:

> **A tool reporting that it wrote a file is not evidence that your bytes are in
> it. Check the size or the hash of what arrived, not the status of the thing
> that sent it.**

This is the same shape as the backup that reported success over an empty
directory, the tar that exited cleanly while its cleanup never ran, and the
version number three sources agreed on without any of them knowing. The rule was
already written down. It had simply not been applied to the act of copying a
file, because copying a file feels too simple to need checking.

One consequence worth recording rather than quietly fixing: `analysis/README.md`
was committed and pushed in `e4d8a43` **in its stale form**, so for a short
period the repository's own documentation still described `features-tty.py` as a
keystroke-timing tool while the script beside it said the opposite. Corrected in
a later commit, and the sequence is left visible here.

---

## The redirect that destroyed the file it was meant to replace

Every file pushed to the sensor today was converted with the same line:

```
sed 's/\r$//' features-files.py.crlf > features-files.py && rm features-files.py.crlf
```

On one attempt the upload had not completed, so the `.crlf` file did not exist.
The shell creates and **truncates the destination before the command on the left
runs**, so the redirect emptied the good copy of `features-files.py`, `sed` then
failed, and `&& rm` never ran. The file was left at zero bytes.

What made it dangerous rather than merely annoying: **an empty Python file runs
silently and exits zero.** Both commands that followed —

```
sudo python3 features-files.py --verify
sudo python3 features-files.py --out ~/analysis/file-features.csv
```

— produced no output whatsoever and returned success. Nothing printed, nothing
failed, nothing written. It looked exactly like a clean finish, and on a day
spent adding loud failure modes to that very script, the script could not speak
because there was none of it left. The only thing that gave it away was the hash:

```
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

which is the SHA-256 of empty input and worth recognising on sight.

**The standing pattern from now on**, which cannot destroy anything, because it
converts in place and renames only on success:

```
sed -i 's/\r$//' <file>.crlf && mv -f <file>.crlf <file>
sha256sum <file>
```

If the upload did not arrive, `sed` fails, `mv` never runs, and the previous good
copy is untouched. The hash is checked before the file is run, not after.

Two lessons, and the second is the general one:

- A redirect is not a safe way to transform a file into itself or over a working
  copy. `sed -i` plus `mv` is, and costs nothing.
- **Silence from a tool is not the same as success, and an empty program is the
  quietest possible failure.** Every loud-failure guard added today lives inside
  the file; none of them survives the file being gone. A check that depends on
  the thing being checked is not a check — which is why the hash, computed
  outside the program, is the one that worked.

---

## The control was working. The alarm said it was not.

`analysis/figures.sh` ends with a section headed *the figure that must be zero*.
It existed because this project had already let the decoy reach the internet for
four days without noticing, and the whole point was that it could never happen
again unnoticed. On 5 October it printed:

```
outbound fetches since the block   455   *** THE BLOCK IS NOT HOLDING ***
Stop. Do not publish any figure until this is explained.
```

The block was holding. Here is the query:

```sql
SELECT COUNT(*) FROM v_events
WHERE eventid LIKE 'cowrie.session.file_%'
  AND json_extract(raw,'$.url') IS NOT NULL
  AND ts > '2026-09-29T12:00:00';
```

`cowrie.session.file_%` matches `file_download.failed`, and a blocked outbound
fetch is logged as `file_download.failed` **carrying the URL it tried**. So the
control working correctly produced every one of the 455 events that the alarm
reported as the control failing. Checked before anything was changed: all 455
are `.failed`, **none records a `shasum` or an `outfile`**, so nothing was ever
retrieved. 24 destinations at the time of checking.

**This is worse than a wrong number, and the reason is the sentence underneath
it.** *Do not publish any figure until this is explained* is a correct
instruction attached to a condition that was permanently true. An alarm that
fires every single run is not a control; it is training. Everybody learns to
scroll past it, and what they have actually learned is to scroll past that
section — including on the day it is right.

The same document already names this failure mode in the other direction: a
dashboard that is green because the query behind it silently returns nothing. A
dashboard that is red because the query counts the wrong rows ends in the same
place, by a route that feels more responsible on the way.

**The fix is two numbers, because there were always two questions.**

```
outbound fetches that SUCCEEDED    0     must be zero
fetch attempts BLOCKED             505   expected to grow
distinct URLs attempted            34
```

The first is scoped to `cowrie.session.file_download` exactly and requires a
`shasum` or an `outfile`, so an attempt cannot be read as a retrieval and an
upload carrying a URL cannot be read as a fetch. The second is the evidence the
control is alive and being exercised, which is a stronger claim than a zero —
and **zero blocked attempts now prints its own warning**, because that would mean
either that nobody is asking the decoy to fetch anything any more or that the
logging of failures has stopped.

Both halves were tested against a stand-in database before shipping: the success
query returns 0 for the real population, ignores a pre-block success and an
upload, and returns 1 when a genuine post-block retrieval is inserted. **A guard
that cannot fire is the other half of this defect**, and testing only that an
alarm stays quiet proves nothing about whether it still works.

What generalises, for a GRC audience:

> **A control and the alarm on that control are two separate things, and each
> needs its own evidence.** The block had been verified against the packet
> filter. The alarm on it had never been verified at all — it had only ever been
> read, and it looked right.

### Where that alarm actually came from, found by auditing rather than remembering

The account above blames the query in `figures.sh`. That is where the defect
*was*, and it is not where it came from. Found a few hours later, by reading
`weekly.sql` on the suspicion that a query-pattern bug would not be alone:

**Query 13 in `weekly.sql` had it right all along.** It tests the eventid as well
as the url, and reports `FETCHED - outbound` separately from
`fetch failed - outbound`:

```sql
WHEN json_extract(raw, '$.url') IS NOT NULL
     AND eventid = 'cowrie.session.file_download'    THEN 'FETCHED - outbound'
WHEN json_extract(raw, '$.url') IS NOT NULL          THEN 'fetch failed - outbound'
```

**The comment four lines above it did not:**

```
url present            we went and got it. OUTBOUND. Must be zero for any
                       timestamp after the block went in on 29 Sept 12:00.
```

`figures.sh` implemented the comment. The correct logic was four lines below, in
the same file, and nobody re-derived the rule from the SELECT because a comment
stated it plainly — which is what comments are for.

> **A correct implementation with a wrong prose summary beside it is more
> dangerous than no summary at all, because the next thing built is built from
> the summary.**

The same wrong discriminator had propagated into the deck's `err-figures`
speaker notes, as the line *"the event carries a url field only when our machine
went and fetched something"*. Corrected in all three places on 5 October.
`docs/rules-of-engagement.md` was checked and was already right: it reports
fetches and failures as separate figures, so the correct understanding existed in
September and was lost in the summarising, not in the analysis.

This is the counterpart to a rule already in this document. *When a thing moves,
go and look at everything that names it* is about a fact that changed. This is
about a fact that never changed and was written down wrongly once: **go and look
at what the code does, not at what the comment says it does — especially when the
comment is the more convenient of the two to read.**

## How fast these figures move

Two runs of `figures.sh` twenty minutes apart, 5 October:

| | 14:55 | 15:02 |
| --- | --- | --- |
| files held in downloads/ | 136 | 138 |
| distinct hashes recorded in the log | 83 | 85 |
| fetch attempts blocked | 455 | 505 |
| distinct URLs attempted | 24 | 34 |

Fifty blocked attempts, two new captures and ten new destinations in twenty
minutes. Every figure in every document is a snapshot, the as-of line is not
decoration, and this is the argument for freezing figures on one date rather than
refreshing them whenever a document is edited.

---

## Corrections owed to this document

**The morning addendum's analyst-exclusion paragraph is superseded.** It ends
*"The address `allow-me.ps1` reports must be appended to `exclude-ips.txt`
before step 5, and `ingest.py` re-run. Still outstanding at the time of
writing."* That is no longer the plan and should not be followed: appending by
hand creates a permanent exclusion. `allow-me.ps1` now records each address with
a UTC timestamp, `backup.ps1` copies the history to the sensor, and `ingest.py`
excludes an address only for the window it was held. The hand-append is the
fallback, not the procedure.

**The morning addendum's figure of 132 TTY recordings is wrong. It is 130.**
The two measurements disagreed, and recordings do not disappear, so rather than
pick one the directory was counted directly:

```
sudo ls -1 /home/cowrie/cowrie/var/lib/cowrie/tty | wc -l
130
```

130 files, plus the `.gitignore` the count excludes. The 132 is left above rather
than edited out, because a figure that moved in the impossible direction is a
finding about the measurement and not just a typo.

---

*Afternoon figures are as at 5 October 2026, 13:17 UTC, from `ingest.py`:
465,004 lines read across 11 Cowrie log files and 2 Conpot files, 454,734 events
that count, 2,262 distinct sources, 80,845 real password attempts, 3,370
successful logins from 562 sources, 130 TTY recordings, and no OT events that
count — the door opens on 6 October. 10,171 attempts remain excluded as
artefacts after 22 were recovered.*

---

# Addendum — 6 October 2026

The OT door opened at 17:42:02 UTC; the opening itself is recorded in
`docs/build.md` under *Order of opening* and in the project's check-in log. This
addendum records the two decisions that came out of the morning's file audit and
one measurement from the evening.

**Two statements the project makes about itself were found false by reading its
own files.** The findings notes had named nine third-party addresses in full
for eleven days against the rules of engagement; redacted and recorded there as
the third self-violation. And nine commits from 5 October carry an AI co-author
trailer, against the note in the check-in log that morning that no trailer was
to be used. **Decision: left as they are, recorded here, and the rule restated —
commits in this repository carry no AI trailer.** Rewriting nine public commits
to remove a line that discloses nothing sensitive would be a worse trade than the
inconsistency; the project already made the same call about its own address.

**A planned analysis was tested before it was started, and survived re-scoped.**
`analysis/overlap-test.py` measured whether sources share credential dictionaries
— the premise under about fifty hours of planned ML work. They do, for about a
fifth of fingerprintable sources, inside a majority that share little or nothing;
and the obvious clustering method reports a 41-source chain with no common
credential as the largest campaign. Details in `analysis/README.md`. The lesson
is the one this document already carries, applied to a plan rather than a figure:
**before committing the hours, run the five-minute measurement the plan assumes.**

*As at 6 October 2026, 18:40 UTC: 2,507 distinct sources, 91,345 real password
attempts, 3,502 successful logins from 601 sources, 97,571 arrivals, and the OT
door's first analyst-excluded records; no external OT source yet.*
