# `isotope config`: a bad cloud-config must not lock the user out

Status: prototype. Tested in a QEMU VM on the i3 image, v0.0.22.

## Why

An Isotope upgrade cannot break the machine: the image is A/B, and the
previous one is one reboot away. The cloud-config has nothing like it. It is
applied again on every boot, it creates the users on every boot, and one wrong
line in it can leave a machine that boots to a login screen with no user to
log in as.

That happened on a real laptop: one line was added to the user entry in
`/oem/90_custom.yaml`, the machine restarted, and the user no longer existed.
The system image was fine. The fallback image and the recovery system did not
help, because every boot entry mounts the same `/oem`. `kairos-agent reset`
keeps `/oem` unless asked not to, and erases the home. The way back was a
live USB.

## What Kairos does today

Read in `kairos-io/kairos` at e907b164 and `mudler/yip` v1.27.0, and tested
with the agent this image ships (v4.5.3-dev.2).

- **Two readers.** yip runs the stages. It reads `/system/oem`, `/oem` and
  `/usr/local/cloud-config`, in that order, every `.yaml` and `.yml` below
  them in name order, **one file at a time**. The collector merges the files
  into one config for the agent's own settings, and only the collector follows
  `config_url`.
- **A file that does not load is skipped as a whole, and on this image so is
  every other file of its directory.** `kairos-agent run-stage` exits 0, and
  the unit is green. Everything in the skipped files is gone for that boot,
  the users included. Tested: a wrong indent, or `shell: [/bin/bash]`, gives
  no user and exit 0, and a good file next to the bad one in `/oem` does not
  create its user either. Kairos master (yip v1.27.0) skips only the bad
  file; the agent in v0.0.22 is older than that.
- **`kairos-agent validate` does not tell.** It checks the Kairos schema, not
  what yip loads. Tested: the `shell: [/bin/bash]` file passes `validate`,
  `kairos-agent config` shows its user, and the boot creates no user.
- **Remote config changes with the network.** A `config_url` that cannot be
  fetched gives an empty config and no error, and nothing keeps a copy. A
  chain of `config_url` has no depth limit. Tested: the stages of a file that
  a `config_url` inside another file points to are **not run**; only its
  settings are merged. Tested: the merged config read early in the boot,
  before the network, differs from the one read a minute later.
- **Nothing is recorded.** No fingerprint of the config, no last good copy,
  no record of which file failed. A failed config does not start the fallback
  image, and the fallback has the same config anyway.

## Goals

- A bad file in `/oem` must not remove the users.
- A check, before the restart, that says what the boot will say.
- Say which file is at fault, and why.
- A name for the config of a machine (a fingerprint), so two machines, or one
  machine at two moments, can be compared.
- What changed, when, and a way back.
- No new way to break a boot: when the tool cannot tell, it changes nothing.

## Non-goals

- A configuration manager. `isotope config` does not write cloud-config for
  the user or push it to other machines.
- Changing what Kairos does with a config. The guard only chooses which copy
  of a file Kairos reads.
- A key-by-key history. The unit is the file, because the file is the unit
  Kairos loads or skips.

## Design

### The check is the boot's own loader

```
kairos-agent run-stage --strict --override-cloud-init-paths DIR isotope-config-check
```

`isotope-config-check` is a stage no file has. The agent loads every file in
`DIR` with the loader it uses at boot, runs no step, and in strict mode exits 1
when a file did not load. `isotope config` copies the files it wants an answer
for into a private directory under `/run/isotope` and runs that. All the files
at once first, then one by one only when that fails, so a good config costs
one call and a bad one is named.

Using the agent, not a YAML library, means the check cannot disagree with the
boot: the same binary gives both answers.

Strict mode also fails for what is not in `DIR`: a `kairos.config_url` on the
kernel command line that cannot be fetched, an agent that crashes. So a "no"
is a verdict on a file only when all of these hold: the exit code is 1, the
agent says no to that file alone, and it says yes to an empty directory
before and after. Anything else is **no verdict**: the guard changes nothing,
the commit records nothing, `check` and `apply` exit 3.

### Generations

A generation is the config of a boot that ended with a user who can log in:

- the path, SHA-256, mode and owner of every cloud-config file, in the order
  Kairos reads them;
- a copy of each file of `/oem` and `/usr/local/cloud-config`, kept by its
  hash. The files of `/system/oem` belong to the image: their hash is
  recorded, no copy is kept, and they are never restored;
- the **fingerprint**: the SHA-256 of the list of paths and hashes;
- the hash of the merged config (`kairos-agent config`) and the sources that
  were merged, URLs without their query and password.

They live in `/oem/.isotope-config/`, mode 0700, the last 5:

```
generations/000007.json     the record
blobs/<sha256>              the copies
rejected/<time>/<path>.rejected   every file the tool replaced or removed,
                                  the last 10 times
events.json, events.log           what the last boot did; everything it did
```

Every write goes through a temporary file in the same directory and a rename.
The guard, the commit, `apply` and `rollback` take a lock on the store, so two
of them never write at once.

`/oem` and not `/usr/local`, because the guard runs in the initramfs stage and
on every boot entry, and `/oem` is what all of them mount. No stored file ends
in `.yaml` or `.yml`, so neither yip nor the collector reads the store. The
copies hold what the files held, secrets included, in the same partition,
readable by root only.

### Three layers

**1. Before the change.** `isotope config check [FILE...]` runs the check and
names each file Kairos would skip. `isotope config apply FILE` checks the
file, refuses one that does not load, and installs the rest into `/oem`
through a rename, so a power cut leaves the old file or the new one. The file
it replaces goes to `rejected/`.

**2. The guard, before Kairos reads `/oem`.**
`/system/oem/07_isotope_config_guard.yaml` runs `isotope config guard` in
`initramfs.before` and again in `boot.before`. yip loads each directory only
when it gets to it, and `/system/oem` comes first in every stage, so a step
there runs before yip parses `/oem` for that stage. The guard checks the files
of the writable directories. For each one that does not load:

- the last generation has another copy of that path: the bad file goes to
  `rejected/`, the copy is put back, and the boot goes on with it;
- it has none, or the same one, or the copy does not load either (the agent
  changed with an upgrade): the file is left as it is. Kairos skips it, as it
  does today.

The guard always exits 0 and stops itself after 90 seconds. With no verdict
it changes nothing. It also runs in the recovery system, which reads the same
`/oem` and creates the same users.

**3. The commit, after the boot stage.** `isotope-config-commit.service` runs
`isotope config commit` after `cos-setup-boot`, which is when `/etc/passwd`
has been written again from the cloud-config.

- A user who can log in exists (a person's user id, a shell that is a
  program): if the files changed, they become a new generation.
- None exists, and the last generation had one, and the files changed since:
  the files of the last generation are put back, the boot stage of those
  directories is run again, and the user is back without a restart. This is
  the case the check cannot see: a file that loads and no longer creates the
  user.
- None exists and the files did not change: the cause is not a config file,
  and nothing is touched.

A set with a file that does not load, or with no verdict, is never recorded.
A machine that never had a login user (an appliance) is never rolled back for
not having one. The unit has 5 minutes and the command stops itself after 4,
so it cannot hold the boot. It does not run in the recovery system.

The rollback runs the whole `boot` stage of `/oem` and
`/usr/local/cloud-config` a second time in that boot. A command there that
must run once per boot runs twice. That is the price of getting the user back
without a restart, and it is paid only on a boot that would otherwise have
ended with no login.

The test for a rollback is "nobody can log in", not "something changed":
removing or renaming a user on purpose is not a failure.

### Reading it back

```
isotope config status [--json] [--remote]
isotope config diff [GEN]
isotope config history
isotope config rollback [GEN] [--yes]
```

`status` prints the fingerprint, whether the files are those of the last good
boot, which files changed since, and what the guard and the commit did in the
last boot, with the reason the loader gave and where the replaced file is.
`--json` is the same for a script, which is the drift check for more than one
machine: equal fingerprints are equal configs. `--remote` also asks the agent
for the merged config, which fetches each `config_url`, and says whether it
changed and which sources were read at the last generation and are not read
now.

`rollback` with no argument goes to the last good generation, or to the one
before it when nothing changed since. It keeps every file it replaces. A
rollback is not a new kind of state: the next good boot records it as a new
generation.

## Remote config

What the prototype does: it records the merged config and its sources in each
generation and reports a change or a missing source.

What it cannot do from outside the agent, and what the right behaviour is:

| A `config_url` is | Today | Should be |
|---|---|---|
| not reachable, or gone | merged as empty, no error | the last good copy is used, and the status says so |
| changed, and it loads | used | used, as a new generation |
| changed, and it does not load | the merge fails, or it is dropped | the last good copy is used, and the status says so |
| a chain | followed without limit | a limit, and a stop on a loop |

That needs the collector to keep the last body it fetched for each URL and to
fall back to it. The copy belongs where the installer already writes fetched
content, `/oem`, mode 0600. A status or a diff must print hashes for remote
content, not the text, and URLs without their query and password.

Two things to know until then. The commit runs before the network is up, so
the merged hash of a generation is often the one without the remote part;
`status --remote` then reports "changed" on a machine where nothing changed.
And a file that only a `config_url` points to can set agent settings but
cannot run stages, so it cannot create a user.

## Limits

- The `rootfs` stage runs before the guard. A file that does not load loses
  its `rootfs` steps on the boot that repairs it.
- The guard repairs files, not directories it cannot write. On a Trusted Boot
  system `/oem` is in an encrypted partition that is open by then; that path
  is not tested yet.
- The check answers "does it load". A file that loads and does something
  wrong, other than removing every user, is not caught.
- A link in `/oem` to a file is part of the config, as it is for yip. When
  the guard repairs it, a regular file takes the place of the link.
- `isotope backup` copies `/oem`, so the store goes into a backup and comes
  back with a restore.
- The first boot has no generation. A file that is bad from the start is
  reported and left.
- The message is in `isotope config status` and the journal. Nothing shows it
  on the login screen or in the tray yet.
- Not in the agent overlay or on a server yet: the commit unit is enabled in
  both image stages, but only the i3 desktop image was booted.

## Tests

`update/config_test.go` runs every path against a stand-in for the agent: the
guard, the commit, the rollback, the store and its pruning, the commands.

The VM test installs the image in QEMU and restarts it three times:

1. A good boot: generation 1 is recorded, `check` passes.
2. A line with a wrong indent is added to the user entry of
   `/oem/90_custom.yaml`. `check` refuses it. After the restart the guard has
   put generation 1's file back, the user exists, and `status` gives the
   loader's error and the path of the rejected file.
3. The file is replaced by one that loads and has no user. After the restart
   the commit has gone back to the last generation and the user exists.

Without the guard, case 2 is the lockout: the same agent, given the same
file, creates no user and exits 0.

## What belongs upstream

In the order of how small they are:

1. `kairos-agent validate` should load the file the way the boot does. Today
   it passes files the boot skips.
2. A fingerprint and a `status` for the config, in the agent.
3. Last-good fallback where the files are loaded (yip's directory loader, or
   immucore and the agent around it), which also covers the `rootfs` stage,
   and the same for `config_url` in the collector.
