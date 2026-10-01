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
The regression suite is nineteen cases, every one either a row seen on this
sensor or a specific defect a previous version had; it caught a bug that had
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

**9. Build the regression fixture early, from real observed rows.** The nineteen
test cases exist because a rule went wrong five times. Two of those five would
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
