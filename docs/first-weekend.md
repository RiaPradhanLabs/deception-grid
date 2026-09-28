# The first weekend — 25 to 28 September 2026

Three days of a machine sitting on the internet doing nothing but answering
the door. This note is written in plain words on purpose: the point of the
project is to say something useful to people who do not work in security.

## The numbers

| | |
|---|---|
| Events recorded | 14,845 (our own test traffic excluded) |
| Different places they came from | **93** |
| Arrivals on the office door (port 22) | 11,942 |
| Arrivals on the old-fashioned door (port 23) | 2,891 |
| Password attempts | 3,043 |
| Times somebody guessed right | 86, from 21 different places |

Roughly **4,800 events and 30 new visitors a day**, at a machine nobody was
told about, that hosts nothing, and that nobody has any reason to want.

## Don't quote the event count

One single address — `109.160.32.157` — produced 4,044 of those 14,845
events. That is **27% of everything from one machine**, with a neighbour on
the same network not far behind.

So "14,845 events" is a misleading headline. It mostly measures how stubborn
a handful of scanners are. **93 distinct sources** is the honest number, and
it is the one to say out loud.

## A correction to what we said on Friday

On day one, every single arrival came in on port 23, and none on port 22.
Written up at the time, it was recorded as a finding.

It was not. It was forty minutes of data. Over three days the real picture is
the other way round — **about four arrivals on port 22 for every one on port
23**. The honest lesson is worth more than the original claim: an hour of
anything looks like a pattern, and the discipline is to wait.

## Three different kinds of visitor

This is the part worth explaining to a general audience, because "we got
attacked 14,000 times" tells them nothing and this tells them something.

### 1. The door-rattlers

The overwhelming majority. Automated programs working through a list of
factory-default passwords, a few seconds apart, never pausing to look at what
they have reached. The passwords they try are not clever:

| Username | Password | Attempts |
|---|---|---|
| root | root | 37 |
| admin | admin | 29 |
| root | xc3511 | 28 |
| root | admin | 20 |
| root | vizxv | 17 |
| root | 888888 | 15 |
| user | user | 14 |
| root | juantech | 14 |

`xc3511` is the password a particular make of cheap security camera shipped
with. `vizxv`, `juantech`, `888888` are the same story for other devices.
These are not guesses at *our* password. They are a list of what other
people's equipment came with from the factory, tried on everything.

### 2. The ones that knock and leave

One address connected more than twenty times, thirteen seconds apart, and
never once tried a password. Not breaking in — taking an inventory. Somebody,
somewhere, now has our address on a list of machines that answer.

Worth counting separately. Lumping it in with password guessing would
overstate how much of this traffic is actually an attempted break-in.

### 3. The one that wanted a lift

At twenty to three on Sunday morning, an address in Vietnam guessed the
password correctly, got in, and then asked our machine to do something
strange: fetch a website that tells you your own IP address.

It did this four times in four minutes.

That is somebody **casing the joint**. They were not interested in our
machine or anything on it. They wanted to know what the rest of the internet
would see if they routed their own traffic *through* us — because a
borrowed address that belongs to somebody else is worth money, and the first
thing you check is whose address you would be borrowing.

Our decoy refused. It logged the request and threw it away:

```
direct-tcp connection request to ip-who.com:80
GET /json/
discarded
```

This matters beyond being a good story. The project's one hard rule is that
the machine **only ever receives — it never sends anything to anyone**. That
was a design promise. On Sunday morning somebody actively tried to make it
send, and it refused. The promise is now a tested one.

There is a symmetry here that is worth noticing. Three days earlier we found
our own honeypot software quietly looking up its public address on startup,
and put it on the list to switch off because it broke the same rule. Same
request, same reason — *what does the world see me as?* One of us was being
careful and one was casing the joint, and the two requests are identical.

## One measurement problem, found and fixed

The two most common "password attempts" in the whole dataset are not password
attempts:

```
enable\x00 / linuxshell\x00    219
system\x00 / shell\x00         216
```

Those are the words attackers type *after* getting in, on devices like
routers, to reach a command prompt. Our honeypot's telnet handling appears to
be reading that stream of commands as if it were somebody typing a username
and password.

Together they account for **435 of 3,043 password attempts — about 14%**.
Left in, they would inflate the headline "attacks" figure by a seventh.

They are excluded from the counts in this note, and the analysis should say
so rather than quietly dropping them.

## What this is evidence for

Nothing here was aimed at us. The machine has no name, no website, no users
and nothing worth stealing. It was found, repeatedly, within seconds, by
programs that do not know or care what it is.

That is the argument for a small manufacturer: **you do not have to be a
target to be attacked.** You only have to be reachable.

And the successful break-ins were not clever. Every one used a password that
was on a published list. The fix costs nothing.
