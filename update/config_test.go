package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeConfigAgent stands in for kairos-agent. Like the real one in strict
// mode, it fails when a file it is given does not load; here a file that
// holds the word BROKEN. Its boot stage creates the user of every file that
// names one with "# user: NAME", the way the real boot stage writes
// /etc/passwd from the cloud-config.
const fakeConfigAgent = `#!/bin/sh
# Strict mode also fails for what is not in the directory, such as a
# config_url on the kernel command line that cannot be fetched.
[ "$FAKE_AGENT" = always-fails ] && [ "$1" = run-stage ] && { printf '\t* could not fetch\n'; exit 1; }
[ "$FAKE_AGENT" = crashes ] && [ "$1" = run-stage ] && exit 2
if [ "$FAKE_AGENT" = flaky ] && [ "$1" = run-stage ]; then
	n=$(cat "$FAKE_COUNT" 2>/dev/null || echo 0); n=$((n + 1)); echo $n > "$FAKE_COUNT"
	case $n in 1|3) printf '\t* could not fetch\n'; exit 1 ;; *) exit 0 ;; esac
fi
case "$1" in
config)
	printf '#cloud-config\n\n# Sources:\n# - /oem/90_custom.yaml\n# - https://user:secret@example.com/c.yaml?token=abc\n#\nhostname: test\n'
	exit 0 ;;
run-stage) ;;
*) exit 2 ;;
esac
shift
strict=0 dirs="" stage=""
while [ $# -gt 0 ]; do
	case "$1" in
	--strict) strict=1 ;;
	--override-cloud-init-paths) shift; dirs="$dirs $1" ;;
	*) stage=$1 ;;
	esac
	shift
done
bad=0
for d in $dirs; do
	for f in $(find "$d" -name '*.yaml' | sort); do
		if grep -q BROKEN "$f"; then
			printf '\t* yaml: line 3: did not find expected key\n'
			bad=1
			continue
		fi
		if [ "$stage" = boot ]; then
			sed -n 's/^# user: \(.*\)$/\1:x:1000:1000::\/home\/\1:\/bin\/sh/p' "$f" >> "$FAKE_PASSWD"
		fi
	done
done
[ $strict = 1 ] && exit $bad
exit 0
`

const goodUser = "#cloud-config\n# user: mauro\nusers:\n  - name: mauro\n"

type configFixture struct {
	t *testing.T
	e configEnv
}

func newConfigFixture(t *testing.T) *configFixture {
	t.Helper()
	root := t.TempDir()
	agent := filepath.Join(root, "agent")
	if err := os.WriteFile(agent, []byte(fakeConfigAgent), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ISOTOPE_UPDATE_AGENT", agent)
	t.Setenv("ISOTOPE_CONFIG_ROOT", root)
	t.Setenv("FAKE_PASSWD", filepath.Join(root, "etc/passwd"))
	e := newConfigEnv()
	clock := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	e.Now = func() time.Time { clock = clock.Add(time.Minute); return clock }
	f := &configFixture{t, e}
	f.write("/bin/sh", "#!/bin/true\n", 0o755)
	f.write("/system/oem/00_rootfs.yaml", "name: image\n", 0o644)
	f.write("/oem/90_custom.yaml", goodUser, 0o600)
	f.passwd(true)
	return f
}

func (f *configFixture) write(path, content string, mode os.FileMode) {
	f.t.Helper()
	p := f.e.real(path)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		f.t.Fatal(err)
	}
}

func (f *configFixture) read(path string) string {
	f.t.Helper()
	data, err := os.ReadFile(f.e.real(path))
	if err != nil {
		f.t.Fatal(err)
	}
	return string(data)
}

// passwd writes /etc/passwd as a boot would leave it, with or without the user.
func (f *configFixture) passwd(user bool) {
	content := "root:x:0:0::/root:/bin/sh\n"
	if user {
		content += "mauro:x:1000:1000::/home/mauro:/bin/sh\n"
	}
	f.write("/etc/passwd", content, 0o644)
}

func (f *configFixture) commit() ([]guardEvent, *generation) {
	f.t.Helper()
	events, g, err := f.e.commit()
	if err != nil {
		f.t.Fatal(err)
	}
	return events, g
}

func (f *configFixture) run(args ...string) (int, string) {
	var out bytes.Buffer
	code := cmdConfig(args, strings.NewReader(""), &out, &out)
	return code, out.String()
}

func TestConfigScanReadsWhatKairosReads(t *testing.T) {
	f := newConfigFixture(t)
	f.write("/oem/95_userdata/user.yml", "name: nested\n", 0o600)
	f.write("/oem/notes.txt", "not a config\n", 0o600)
	f.write("/oem/grubenv", "# GRUB\n", 0o600)
	f.write("/usr/local/cloud-config/10_extra.yaml", "name: extra\n", 0o600)
	files, err := f.e.scan()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, c := range files {
		got = append(got, c.Path)
	}
	want := "/system/oem/00_rootfs.yaml /oem/90_custom.yaml /oem/95_userdata/user.yml /usr/local/cloud-config/10_extra.yaml"
	if strings.Join(got, " ") != want {
		t.Fatalf("scan = %v, want %s", got, want)
	}
	if files[0].Writable || !files[1].Writable {
		t.Fatalf("writable flags are wrong: %+v", files[:2])
	}
	before := fingerprint(files)
	f.write("/oem/90_custom.yaml", goodUser+"# a change\n", 0o600)
	after, _ := f.e.scan()
	if fingerprint(after) == before {
		t.Fatal("the fingerprint did not change with a file")
	}
}

func TestConfigCommitRecordsAGoodBootOnce(t *testing.T) {
	f := newConfigFixture(t)
	_, g := f.commit()
	if g == nil || g.ID != 1 || !g.Login {
		t.Fatalf("first commit = %+v, want generation 1 with a login", g)
	}
	if g.Merged == "" || len(g.Sources) != 2 || g.Sources[1] != "https://example.com/c.yaml" {
		t.Fatalf("merged = %q sources = %v, want the hash and a URL without its secrets", g.Merged, g.Sources)
	}
	if _, again := f.commit(); again != nil {
		t.Fatalf("an unchanged config was recorded again: %+v", again)
	}
	// The kept copy must not be a file Kairos reads.
	files, _ := f.e.scan()
	if len(files) != 2 {
		t.Fatalf("the store added files Kairos would read: %+v", files)
	}
}

// The Dell event: one wrong line in the file that holds the user.
func TestConfigGuardPutsBackTheLastGoodCopy(t *testing.T) {
	f := newConfigFixture(t)
	f.commit()
	f.write("/oem/91_other.yaml", "name: untouched\n", 0o600)
	broken := goodUser + "  shell: /bin/bash BROKEN\n"
	f.write("/oem/90_custom.yaml", broken, 0o600)

	events := f.e.guard()
	if len(events) != 1 || events[0].Action != "restored" || events[0].Path != "/oem/90_custom.yaml" {
		t.Fatalf("guard = %+v, want one restored file", events)
	}
	if !strings.Contains(events[0].Reason, "did not find expected key") {
		t.Fatalf("the reason does not carry the loader's error: %q", events[0].Reason)
	}
	if got := f.read("/oem/90_custom.yaml"); got != goodUser {
		t.Fatalf("the file was not put back: %q", got)
	}
	if got := f.read(events[0].Saved); got != broken {
		t.Fatalf("the rejected file was not kept: %q", got)
	}
	if strings.HasSuffix(events[0].Saved, ".yaml") {
		t.Fatalf("the rejected copy %s is a file Kairos would read", events[0].Saved)
	}
	if got := f.read("/oem/91_other.yaml"); got != "name: untouched\n" {
		t.Fatalf("a good file was changed: %q", got)
	}
	if again := f.e.guard(); len(again) != 0 {
		t.Fatalf("the guard acted on a repaired config: %+v", again)
	}

	// The guard runs twice in a boot. The second run finds nothing, and must
	// not hide what the first one did; the next boot starts a new record.
	f.write("/proc/sys/kernel/random/boot_id", "boot-1\n", 0o444)
	f.e.record(events)
	f.e.record(nil)
	if got := f.e.events(); len(got) != 1 || got[0].Action != "restored" {
		t.Fatalf("events of the boot = %+v, want the restore", got)
	}
	if _, out := f.run("status"); !strings.Contains(out, "restored /oem/90_custom.yaml") {
		t.Fatalf("status does not report the restore: %q", out)
	}
	os.Remove(f.e.real("/proc/sys/kernel/random/boot_id"))
	f.write("/proc/sys/kernel/random/boot_id", "boot-2\n", 0o444)
	f.e.record(nil)
	if got := f.e.events(); len(got) != 0 {
		t.Fatalf("a new boot kept the events of the one before: %+v", got)
	}
}

func TestConfigGuardLeavesWhatItCannotRepair(t *testing.T) {
	f := newConfigFixture(t)
	// No generation yet: nothing to put back.
	f.write("/oem/90_custom.yaml", "BROKEN\n", 0o600)
	events := f.e.guard()
	if len(events) != 1 || events[0].Action != "left" {
		t.Fatalf("guard = %+v, want the file left", events)
	}
	if f.read("/oem/90_custom.yaml") != "BROKEN\n" {
		t.Fatal("the guard changed a file it had no copy of")
	}
}

func TestConfigGuardChangesNothingWithoutAVerdict(t *testing.T) {
	f := newConfigFixture(t)
	f.commit()
	f.write("/oem/90_custom.yaml", "BROKEN\n", 0o600)
	t.Setenv("ISOTOPE_UPDATE_AGENT", "/nonexistent/kairos-agent")
	events := f.e.guard()
	if len(events) != 1 || events[0].Action != "skipped" {
		t.Fatalf("guard = %+v, want skipped", events)
	}
	if f.read("/oem/90_custom.yaml") != "BROKEN\n" {
		t.Fatal("the guard changed a file without a verdict from kairos-agent")
	}
}

// A file that loads but no longer creates the user.
func TestConfigCommitGoesBackWhenNobodyCanLogIn(t *testing.T) {
	f := newConfigFixture(t)
	f.commit()
	f.write("/oem/90_custom.yaml", "#cloud-config\nhostname: nobody\n", 0o600)
	f.write("/oem/92_new.yaml", "name: added\n", 0o600)
	f.passwd(false) // what the boot stage left

	events, g := f.commit()
	if g != nil {
		t.Fatalf("a boot with no login was recorded: %+v", g)
	}
	last := events[len(events)-1]
	if last.Action != "rolled back" || !strings.Contains(last.Reason, "the user is back") {
		t.Fatalf("commit = %+v, want a rollback that brings the user back", events)
	}
	if f.read("/oem/90_custom.yaml") != goodUser {
		t.Fatal("the last good file was not restored")
	}
	if _, err := os.Stat(f.e.real("/oem/92_new.yaml")); !os.IsNotExist(err) {
		t.Fatal("a file that is not in the generation was left in /oem")
	}
	if !f.e.canLogin() {
		t.Fatal("the boot stage of the restored files did not create the user")
	}
	if len(f.e.generations()) != 1 {
		t.Fatal("the rollback changed the generations")
	}
}

func TestConfigCommitDoesNotBlameAnUnchangedConfig(t *testing.T) {
	f := newConfigFixture(t)
	f.commit()
	f.passwd(false)
	events, g := f.commit()
	if g != nil || len(events) != 1 || events[0].Action != "left" {
		t.Fatalf("commit = %+v %+v, want one left event", events, g)
	}
}

func TestConfigCommitRefusesAConfigWithABadFile(t *testing.T) {
	f := newConfigFixture(t)
	f.commit()
	f.write("/oem/92_new.yaml", "BROKEN\n", 0o600)
	events, g := f.commit()
	if g != nil || len(events) != 1 || events[0].Action != "not committed" {
		t.Fatalf("commit = %+v %+v, want not committed", events, g)
	}
}

func TestConfigAFirstBootWithoutAUserNeverRollsBack(t *testing.T) {
	f := newConfigFixture(t)
	f.passwd(false)
	_, g := f.commit()
	if g == nil || g.Login {
		t.Fatalf("commit = %+v, want a generation without a login", g)
	}
	// A server with no person on it: the next change is not a lockout.
	f.write("/oem/92_new.yaml", "name: added\n", 0o600)
	events, g := f.commit()
	if g == nil || len(events) != 0 {
		t.Fatalf("commit = %+v %+v, want generation 2", events, g)
	}
}

func TestConfigKeepsTheLastGenerations(t *testing.T) {
	f := newConfigFixture(t)
	for i := 0; i < configKeep+3; i++ {
		f.write("/oem/90_custom.yaml", goodUser+strings.Repeat("# x\n", i), 0o600)
		f.commit()
	}
	gens := f.e.generations()
	if len(gens) != configKeep || gens[len(gens)-1].ID != configKeep+3 {
		t.Fatalf("kept %d generations, last %d", len(gens), gens[len(gens)-1].ID)
	}
	blobs, _ := os.ReadDir(f.e.blobDir())
	if len(blobs) != configKeep {
		t.Fatalf("kept %d copies, want %d", len(blobs), configKeep)
	}
}

func TestConfigCommands(t *testing.T) {
	f := newConfigFixture(t)

	if code, out := f.run("status"); code != exitOK || !strings.Contains(out, "no generation yet") {
		t.Fatalf("status = %d %q", code, out)
	}
	f.commit()

	// apply refuses a file that does not load, and changes nothing.
	cand := filepath.Join(t.TempDir(), "90_custom.yaml")
	os.WriteFile(cand, []byte("BROKEN\n"), 0o600)
	if code, out := f.run("apply", cand); code != exitError || !strings.Contains(out, "nothing was changed") {
		t.Fatalf("apply of a bad file = %d %q", code, out)
	}
	if f.read("/oem/90_custom.yaml") != goodUser {
		t.Fatal("apply installed a file that does not load")
	}

	changed := goodUser + "    shell: /bin/bash\n"
	os.WriteFile(cand, []byte(changed), 0o600)
	if code, out := f.run("apply", cand); code != exitOK {
		t.Fatalf("apply = %d %q", code, out)
	}
	if f.read("/oem/90_custom.yaml") != changed {
		t.Fatal("apply did not install the file")
	}

	code, out := f.run("status")
	if code != exitOK || !strings.Contains(out, "changed since generation 1") || !strings.Contains(out, "changed  /oem/90_custom.yaml") {
		t.Fatalf("status = %d %q", code, out)
	}
	code, out = f.run("diff")
	if code != exitOK || !strings.Contains(out, "+   5      shell: /bin/bash") {
		t.Fatalf("diff = %d %q", code, out)
	}
	if code, out = f.run("check"); code != exitOK || !strings.Contains(out, "ok   /oem/90_custom.yaml") {
		t.Fatalf("check = %d %q", code, out)
	}

	// Not yet proven by a boot: rollback goes to generation 1.
	if code, out = f.run("rollback", "--yes"); code != exitOK || !strings.Contains(out, "generation 1") {
		t.Fatalf("rollback = %d %q", code, out)
	}
	if f.read("/oem/90_custom.yaml") != goodUser {
		t.Fatal("rollback did not restore generation 1")
	}

	// After a good boot of the change, rollback goes one further back.
	f.write("/oem/90_custom.yaml", changed, 0o600)
	if _, g := f.commit(); g == nil || g.ID != 2 {
		t.Fatalf("commit = %+v, want generation 2", g)
	}
	if code, out = f.run("rollback", "--yes"); code != exitOK || !strings.Contains(out, "generation 1") {
		t.Fatalf("rollback = %d %q", code, out)
	}
	if f.read("/oem/90_custom.yaml") != goodUser {
		t.Fatal("rollback did not go to the generation before")
	}
	if code, out = f.run("history"); code != exitOK || !strings.Contains(out, "changed /oem/90_custom.yaml") {
		t.Fatalf("history = %d %q", code, out)
	}

	f.write("/oem/90_custom.yaml", "BROKEN\n", 0o600)
	if code, out = f.run("check"); code != exitError || !strings.Contains(out, "BAD  /oem/90_custom.yaml") {
		t.Fatalf("check of a bad file = %d %q", code, out)
	}
	if code, _ = f.run("nonsense"); code != exitUsage {
		t.Fatalf("unknown command = %d", code)
	}
}

func TestRedactURL(t *testing.T) {
	for in, want := range map[string]string{
		"/oem/90_custom.yaml":                          "/oem/90_custom.yaml",
		"https://example.com/a.yaml":                   "https://example.com/a.yaml",
		"https://user:pw@example.com/a.yaml?token=abc": "https://example.com/a.yaml",
		"https://example.com/a@b.yaml#frag":            "https://example.com/a@b.yaml",
	} {
		if got := redactURL(in); got != want {
			t.Errorf("redactURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLineDiff(t *testing.T) {
	got := strings.Join(lineDiff("a\nb\nc\n", "a\nB\nc\nd\n"), "|")
	want := "-   2  b|+   2  B|+   4  d"
	if got != want {
		t.Fatalf("lineDiff = %q, want %q", got, want)
	}
}

// kairos-agent in strict mode fails for more than a bad file. A "no" that it
// also gives to an empty directory, or a crash, is not a verdict on any file.
func TestConfigANoThatIsNotAboutTheFilesChangesNothing(t *testing.T) {
	for _, mode := range []string{"always-fails", "crashes"} {
		t.Run(mode, func(t *testing.T) {
			f := newConfigFixture(t)
			f.commit()
			edited := goodUser + "# a good edit, not yet proven by a boot\n"
			f.write("/oem/90_custom.yaml", edited, 0o600)
			t.Setenv("FAKE_AGENT", mode)

			events := f.e.guard()
			if len(events) != 1 || events[0].Action != "skipped" {
				t.Fatalf("guard = %+v, want skipped", events)
			}
			if f.read("/oem/90_custom.yaml") != edited {
				t.Fatal("the guard replaced a good file on an answer that was not about it")
			}
			events, g := f.commit()
			if g != nil || len(events) != 1 || events[0].Action != "not committed" {
				t.Fatalf("commit = %+v %+v, want not committed: a config not known to load is not a generation", events, g)
			}
			if code, _ := f.run("check"); code != exitNoVerdict {
				t.Fatalf("check = %d, want %d (no verdict)", code, exitNoVerdict)
			}
			cand := filepath.Join(t.TempDir(), "90_custom.yaml")
			os.WriteFile(cand, []byte(goodUser), 0o600)
			if code, _ := f.run("apply", cand); code != exitNoVerdict {
				t.Fatalf("apply = %d, want %d (no verdict)", code, exitNoVerdict)
			}
			if f.read("/oem/90_custom.yaml") != edited {
				t.Fatal("apply installed a file without a verdict")
			}
		})
	}
}

func TestConfigGuardRunsOutOfTimeWithoutChangingAnything(t *testing.T) {
	f := newConfigFixture(t)
	f.commit()
	f.write("/oem/90_custom.yaml", "BROKEN\n", 0o600)
	f.e.Until = time.Now().Add(-time.Second)
	if events := f.e.guard(); len(events) != 1 || events[0].Action != "skipped" {
		t.Fatalf("guard = %+v, want skipped", events)
	}
	if f.read("/oem/90_custom.yaml") != "BROKEN\n" {
		t.Fatal("the guard changed a file after its time was up")
	}
}

// yip follows a link to a file, so a link is part of the config.
func TestConfigScanFollowsALinkToAFile(t *testing.T) {
	f := newConfigFixture(t)
	f.write("/usr/local/real.txt", "BROKEN\n", 0o600)
	if err := os.Symlink(f.e.real("/usr/local/real.txt"), f.e.real("/oem/95_link.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(f.e.real("/nowhere"), f.e.real("/oem/96_dangling.yaml")); err != nil {
		t.Fatal(err)
	}
	code, out := f.run("check")
	if code != exitError || !strings.Contains(out, "BAD  /oem/95_link.yaml") || strings.Contains(out, "96_dangling") {
		t.Fatalf("check = %d %q, want the link reported and the dangling one left out", code, out)
	}
}

func TestConfigReplacedFilesKeepTheirPath(t *testing.T) {
	f := newConfigFixture(t)
	f.write("/oem/a__b.yaml", "one\n", 0o600)
	f.write("/oem/a/b.yaml", "two\n", 0o600)
	x, err := f.e.setAside("/oem/a__b.yaml", "stamp")
	if err != nil {
		t.Fatal(err)
	}
	y, err := f.e.setAside("/oem/a/b.yaml", "stamp")
	if err != nil {
		t.Fatal(err)
	}
	if x == y || f.read(x) != "one\n" || f.read(y) != "two\n" {
		t.Fatalf("two replaced files share a copy: %s %s", x, y)
	}
	for _, p := range []string{x, y} {
		if ext := filepath.Ext(p); ext == ".yaml" || ext == ".yml" {
			t.Fatalf("the copy %s is a file Kairos would read", p)
		}
	}
}

func TestConfigApplyKeepsTheFileItReplaces(t *testing.T) {
	f := newConfigFixture(t)
	cand := filepath.Join(t.TempDir(), "new.yaml")
	os.WriteFile(cand, []byte("name: new\n"), 0o600)
	code, out := f.run("apply", cand, "--as", "90_custom.yaml")
	if code != exitOK || f.read("/oem/90_custom.yaml") != "name: new\n" {
		t.Fatalf("apply = %d %q", code, out)
	}
	saved, _ := filepath.Glob(f.e.real("/oem/.isotope-config/rejected/*/oem/90_custom.yaml.rejected"))
	if len(saved) != 1 {
		t.Fatalf("the replaced file was not kept: %v", saved)
	}
	if data, _ := os.ReadFile(saved[0]); string(data) != goodUser {
		t.Fatalf("the kept file is not the one that was replaced: %q", data)
	}
	left, _ := filepath.Glob(f.e.real("/oem/.isotope-*"))
	for _, l := range left {
		if filepath.Base(l) != ".isotope-config" {
			t.Fatalf("a temporary file was left in /oem: %s", l)
		}
	}
}

func TestConfigRollbackTakesItsFlagsInAnyOrder(t *testing.T) {
	f := newConfigFixture(t)
	f.commit()
	changed := goodUser + "# changed\n"
	f.write("/oem/90_custom.yaml", changed, 0o600)
	// Declined (no answer on stdin): nothing changes, and it does not say ok.
	if code, _ := f.run("rollback", "1"); code != exitError || f.read("/oem/90_custom.yaml") != changed {
		t.Fatalf("a declined rollback = %d, or it changed the file", code)
	}
	if code, out := f.run("rollback", "1", "--yes"); code != exitOK || f.read("/oem/90_custom.yaml") != goodUser {
		t.Fatalf("rollback 1 --yes = %d %q", code, out)
	}
	if code, _ := f.run("rollback", "1", "2"); code != exitUsage {
		t.Fatalf("rollback with two generations = %d, want usage", code)
	}
}

func TestConfigKeepsTheLastReplacedSets(t *testing.T) {
	f := newConfigFixture(t)
	// The clock goes backwards, as on a machine with a dead battery: the
	// newest set must still be the one that stays.
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	f.e.Now = func() time.Time { clock = clock.Add(-time.Hour); return clock }
	var last string
	for i := 0; i < configKeepRejected+4; i++ {
		set := f.e.newSet()
		if set == last {
			t.Fatalf("two commands share the set %s", set)
		}
		last = set
		if _, err := f.e.setAside("/oem/90_custom.yaml", set); err != nil {
			t.Fatal(err)
		}
	}
	f.e.pruneRejected()
	sets, _ := os.ReadDir(f.e.real("/oem/.isotope-config/rejected"))
	if len(sets) != configKeepRejected || !strings.HasPrefix(sets[0].Name(), "000005-") || sets[len(sets)-1].Name() != last {
		t.Fatalf("kept %d sets, from %s to %s, want the last %d", len(sets), sets[0].Name(), sets[len(sets)-1].Name(), configKeepRejected)
	}
}

// An answer that does not repeat is not about the file.
func TestConfigAFailureThatDoesNotRepeatIsNotAVerdict(t *testing.T) {
	f := newConfigFixture(t)
	f.commit()
	edited := goodUser + "# a good edit\n"
	f.write("/oem/90_custom.yaml", edited, 0o600)
	// Fails the first call (all files) and the third (the file alone); the
	// control between them and the second ask pass.
	t.Setenv("FAKE_AGENT", "flaky")
	t.Setenv("FAKE_COUNT", filepath.Join(t.TempDir(), "count"))
	events := f.e.guard()
	if len(events) != 1 || events[0].Action != "skipped" || f.read("/oem/90_custom.yaml") != edited {
		t.Fatalf("guard = %+v, want skipped and the file untouched", events)
	}
}

func TestConfigGuardLeavesAFileWhoseLastGoodCopyDoesNotLoad(t *testing.T) {
	f := newConfigFixture(t)
	_, g := f.commit()
	// The agent of a new image no longer loads what the old one did.
	blob := f.e.blob(byPath(g.Files)["/oem/90_custom.yaml"].SHA256)
	os.WriteFile(blob, []byte("BROKEN\n"), 0o600)
	f.write("/oem/90_custom.yaml", "BROKEN too\n", 0o600)
	events := f.e.guard()
	if len(events) != 1 || events[0].Action != "left" || f.read("/oem/90_custom.yaml") != "BROKEN too\n" {
		t.Fatalf("guard = %+v, want the file left", events)
	}
}

func TestConfigLockDoesNotWaitPastItsTime(t *testing.T) {
	f := newConfigFixture(t)
	unlock, err := f.e.lock()
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	second := f.e
	second.Until = time.Now().Add(200 * time.Millisecond)
	start := time.Now()
	if _, err := second.lock(); err == nil {
		t.Fatal("two commands hold the lock")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("the lock waited %s past its time", time.Since(start))
	}
}
