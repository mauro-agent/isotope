package main

// isotope config: a safety net for the cloud-config files of this machine.
//
// Kairos applies the cloud-config on every boot, one file at a time, from
// /system/oem, /oem and /usr/local/cloud-config. A file that does not load is
// skipped as a whole and the boot goes on, so one wrong line in the file that
// holds the user leaves a machine nobody can log in to. /oem is shared by
// every boot entry, so the fallback and the recovery system do not help.
//
// This command gives the config what the system image already has:
//
//   - a check that uses the loader of the boot itself (kairos-agent), so it
//     says what the boot will say, per file;
//   - generations: the files of each boot that ended with a user who can log
//     in, kept by content hash under /oem/.isotope-config;
//   - a guard at boot that puts back the last good copy of a file that no
//     longer loads, before Kairos reads it;
//   - a commit after the boot that records a new generation, or goes back to
//     the last one when the boot left no user who can log in;
//   - a fingerprint, a diff, a history and a rollback.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// configKeep is how many generations stay on the OEM partition, which is small.
const configKeep = 5

// configCheckStage is a stage no cloud-config has. Running it makes
// kairos-agent load every file and run no step.
const configCheckStage = "isotope-config-check"

// configDir is one directory Kairos reads cloud-config from.
type configDir struct {
	Path string
	// Writable is false for /system/oem, which is part of the image: its
	// files are recorded by hash but never kept or restored.
	Writable bool
}

// configEnv is where everything is. ISOTOPE_CONFIG_ROOT moves all of it
// under another directory, for the tests.
type configEnv struct {
	Root   string
	Dirs   []configDir // in the order Kairos reads them
	State  string
	Passwd string
	Tmp    string
	Now    func() time.Time
}

func newConfigEnv() configEnv {
	root := os.Getenv("ISOTOPE_CONFIG_ROOT")
	return configEnv{
		Root: root,
		Dirs: []configDir{
			{Path: "/system/oem"},
			{Path: "/oem", Writable: true},
			{Path: "/usr/local/cloud-config", Writable: true},
		},
		State:  "/oem/.isotope-config",
		Passwd: "/etc/passwd",
		Tmp:    "/run/isotope",
		Now:    time.Now,
	}
}

// real is the path on disk of a path of the system.
func (e configEnv) real(p string) string { return filepath.Join(e.Root, p) }

// configFile is one cloud-config file as it was read.
type configFile struct {
	Path     string      `json:"path"`
	SHA256   string      `json:"sha256"`
	Size     int64       `json:"size"`
	Mode     fs.FileMode `json:"mode"`
	UID      int         `json:"uid"`
	GID      int         `json:"gid"`
	Writable bool        `json:"writable"`
}

// generation is the config of one good boot.
type generation struct {
	ID          int          `json:"id"`
	Time        time.Time    `json:"time"`
	Reason      string       `json:"reason"`
	Fingerprint string       `json:"fingerprint"`
	Files       []configFile `json:"files"`
	// Merged is the hash of what `kairos-agent config` printed: the merged
	// config, with the content of each config_url. Empty when unknown.
	Merged string `json:"merged,omitempty"`
	// Sources are the files and the URLs that were merged, URLs without
	// their query and password.
	Sources []string `json:"sources,omitempty"`
	// Login is true when a user who can log in existed after that boot.
	Login bool `json:"login"`
}

// guardEvent is one thing the guard or the commit did, for the user to read.
type guardEvent struct {
	Time   time.Time `json:"time"`
	Stage  string    `json:"stage"`
	Path   string    `json:"path,omitempty"`
	Action string    `json:"action"`
	Reason string    `json:"reason,omitempty"`
	Saved  string    `json:"saved,omitempty"`
}

// scan reads the cloud-config files the way Kairos does: each directory in
// turn, every .yaml and .yml below it, in name order.
func (e configEnv) scan() ([]configFile, error) {
	var out []configFile
	for _, d := range e.Dirs {
		base := e.real(d.Path)
		err := filepath.WalkDir(base, func(p string, de fs.DirEntry, err error) error {
			if err != nil {
				if p == base {
					return fs.SkipAll // a directory that is not there
				}
				return nil
			}
			if !de.Type().IsRegular() {
				return nil
			}
			if ext := filepath.Ext(p); ext != ".yaml" && ext != ".yml" {
				return nil
			}
			data, err := os.ReadFile(p)
			if err != nil {
				return fmt.Errorf("reading %s: %w", p, err)
			}
			info, err := de.Info()
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(base, p)
			sum := sha256.Sum256(data)
			uid, gid := owner(info)
			out = append(out, configFile{
				UID: uid, GID: gid,
				Path:     filepath.Join(d.Path, rel),
				SHA256:   hex.EncodeToString(sum[:]),
				Size:     info.Size(),
				Mode:     info.Mode().Perm(),
				Writable: d.Writable,
			})
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// fingerprint names a set of files: the same files with the same content in
// the same order give the same fingerprint on every machine.
func fingerprint(files []configFile) string {
	h := sha256.New()
	for _, f := range files {
		fmt.Fprintf(h, "%s\x00%s\n", f.Path, f.SHA256)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func writable(files []configFile) []configFile {
	var out []configFile
	for _, f := range files {
		if f.Writable {
			out = append(out, f)
		}
	}
	return out
}

func byPath(files []configFile) map[string]configFile {
	m := make(map[string]configFile, len(files))
	for _, f := range files {
		m[f.Path] = f
	}
	return m
}

// --- the store ---------------------------------------------------------

func (e configEnv) genDir() string  { return filepath.Join(e.real(e.State), "generations") }
func (e configEnv) blobDir() string { return filepath.Join(e.real(e.State), "blobs") }
func (e configEnv) blob(sum string) string {
	return filepath.Join(e.blobDir(), sum)
}

// generations returns the stored generations, oldest first. One that cannot
// be read is left out: a damaged record must not stop a boot.
func (e configEnv) generations() []generation {
	names, _ := filepath.Glob(filepath.Join(e.genDir(), "*.json"))
	sort.Strings(names)
	var out []generation
	for _, n := range names {
		data, err := os.ReadFile(n)
		if err != nil {
			continue
		}
		var g generation
		if json.Unmarshal(data, &g) != nil || g.ID == 0 {
			continue
		}
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (e configEnv) latest() *generation {
	gens := e.generations()
	if len(gens) == 0 {
		return nil
	}
	return &gens[len(gens)-1]
}

// writeAtomic writes a file through a temporary name that Kairos does not
// read (no .yaml), so a power cut leaves the old file or the new one.
func writeAtomic(path string, data []byte, mode fs.FileMode) error {
	tmp := path + ".isotope-tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(tmp, mode)
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}

// save records the files as a new generation and keeps a copy of each file
// of a writable directory.
func (e configEnv) save(files []configFile, reason string, login bool, merged string, sources []string) (*generation, error) {
	for _, d := range []string{e.real(e.State), e.genDir(), e.blobDir()} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	for _, f := range files {
		if !f.Writable {
			continue
		}
		if _, err := os.Stat(e.blob(f.SHA256)); err == nil {
			continue
		}
		data, err := os.ReadFile(e.real(f.Path))
		if err != nil {
			return nil, err
		}
		if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != f.SHA256 {
			return nil, fmt.Errorf("%s changed while it was saved", f.Path)
		}
		if err := writeAtomic(e.blob(f.SHA256), data, 0o600); err != nil {
			return nil, err
		}
	}
	id := 1
	if l := e.latest(); l != nil {
		id = l.ID + 1
	}
	g := &generation{
		ID: id, Time: e.Now().UTC().Truncate(time.Second), Reason: reason,
		Fingerprint: fingerprint(files), Files: files,
		Merged: merged, Sources: sources, Login: login,
	}
	data, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return nil, err
	}
	name := filepath.Join(e.genDir(), fmt.Sprintf("%06d.json", id))
	if err := writeAtomic(name, append(data, '\n'), 0o600); err != nil {
		return nil, err
	}
	e.prune()
	return g, nil
}

// prune drops the oldest generations and the copies nothing refers to.
func (e configEnv) prune() {
	gens := e.generations()
	for len(gens) > configKeep {
		os.Remove(filepath.Join(e.genDir(), fmt.Sprintf("%06d.json", gens[0].ID)))
		gens = gens[1:]
	}
	used := map[string]bool{}
	for _, g := range gens {
		for _, f := range g.Files {
			used[f.SHA256] = true
		}
	}
	blobs, _ := os.ReadDir(e.blobDir())
	for _, b := range blobs {
		if !used[b.Name()] {
			os.Remove(filepath.Join(e.blobDir(), b.Name()))
		}
	}
}

// setAside keeps a copy of a file that is about to be replaced or removed,
// under a name Kairos does not read. It returns where the copy is.
func (e configEnv) setAside(path, stamp string) (string, error) {
	data, err := os.ReadFile(e.real(path))
	if err != nil {
		return "", err
	}
	name := strings.ReplaceAll(strings.TrimPrefix(path, "/"), "/", "__") + ".rejected"
	dst := filepath.Join(e.State, "rejected", stamp, name)
	if err := os.MkdirAll(filepath.Dir(e.real(dst)), 0o700); err != nil {
		return "", err
	}
	return dst, writeAtomic(e.real(dst), data, 0o600)
}

// restoreFile puts the copy of one file of a generation back.
func (e configEnv) restoreFile(f configFile) error {
	data, err := os.ReadFile(e.blob(f.SHA256))
	if err != nil {
		return err
	}
	if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != f.SHA256 {
		return fmt.Errorf("the kept copy of %s is damaged", f.Path)
	}
	if err := os.MkdirAll(filepath.Dir(e.real(f.Path)), 0o755); err != nil {
		return err
	}
	mode := f.Mode
	if mode == 0 {
		mode = 0o600
	}
	if err := writeAtomic(e.real(f.Path), data, mode); err != nil {
		return err
	}
	// The installer makes /oem's files readable by the admin group; keep
	// that. Not being root (a test) is not a reason to fail.
	os.Chown(e.real(f.Path), f.UID, f.GID)
	return nil
}

func owner(info fs.FileInfo) (uid, gid int) {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid), int(st.Gid)
	}
	return 0, 0
}

// restoreSet makes the writable directories hold exactly the files of the
// generation. Every file it replaces or removes is set aside first.
func (e configEnv) restoreSet(g *generation, stage string) ([]guardEvent, error) {
	cur, err := e.scan()
	if err != nil {
		return nil, err
	}
	stamp := e.Now().UTC().Format("20060102-150405")
	want := byPath(writable(g.Files))
	have := byPath(writable(cur))
	var events []guardEvent
	// Check every copy first: a rollback that stops half way is worse than none.
	for _, f := range want {
		if h, ok := have[f.Path]; ok && h.SHA256 == f.SHA256 {
			continue
		}
		if _, err := os.Stat(e.blob(f.SHA256)); err != nil {
			return nil, fmt.Errorf("generation %d has no copy of %s", g.ID, f.Path)
		}
	}
	paths := make([]string, 0, len(want)+len(have))
	for p := range want {
		paths = append(paths, p)
	}
	for p := range have {
		if _, ok := want[p]; !ok {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)
	for _, p := range paths {
		w, inGen := want[p]
		h, onDisk := have[p]
		if inGen && onDisk && w.SHA256 == h.SHA256 {
			continue
		}
		ev := guardEvent{Time: e.Now().UTC().Truncate(time.Second), Stage: stage, Path: p}
		if onDisk {
			if ev.Saved, err = e.setAside(p, stamp); err != nil {
				return events, err
			}
		}
		if inGen {
			if err := e.restoreFile(w); err != nil {
				return events, err
			}
			ev.Action = "restored"
		} else {
			if err := os.Remove(e.real(p)); err != nil {
				return events, err
			}
			ev.Action = "removed"
		}
		ev.Reason = fmt.Sprintf("back to generation %d", g.ID)
		events = append(events, ev)
	}
	return events, nil
}

// --- events ------------------------------------------------------------

func (e configEnv) eventsPath() string { return filepath.Join(e.real(e.State), "events.json") }

// bootEvents is what the guard and the commit did in one boot.
type bootEvents struct {
	Boot   string       `json:"boot"`
	Events []guardEvent `json:"events"`
}

// bootID names the running boot. It is the same in the initramfs stage and
// after it, so the two runs of the guard and the commit share one record.
func (e configEnv) bootID() string {
	data, _ := os.ReadFile(e.real("/proc/sys/kernel/random/boot_id"))
	return strings.TrimSpace(string(data))
}

// events are what the last boot that ran the guard did.
func (e configEnv) events() []guardEvent {
	var be bootEvents
	if data, err := os.ReadFile(e.eventsPath()); err == nil {
		json.Unmarshal(data, &be)
	}
	return be.Events
}

// record keeps the events for `isotope config status`. The first record of a
// boot drops what the boot before left; later ones in the same boot add to
// it. The log keeps everything.
func (e configEnv) record(events []guardEvent) {
	if err := os.MkdirAll(e.real(e.State), 0o700); err != nil {
		return
	}
	var be bootEvents
	if data, err := os.ReadFile(e.eventsPath()); err == nil {
		json.Unmarshal(data, &be)
	}
	if id := e.bootID(); be.Boot != id || id == "" {
		be = bootEvents{Boot: id}
	}
	be.Events = append(be.Events, events...)
	if be.Events == nil {
		be.Events = []guardEvent{}
	}
	if data, err := json.MarshalIndent(be, "", "  "); err == nil {
		writeAtomic(e.eventsPath(), append(data, '\n'), 0o600)
	}
	if len(events) == 0 {
		return
	}
	f, err := os.OpenFile(filepath.Join(e.real(e.State), "events.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	for _, ev := range events {
		if line, err := json.Marshal(ev); err == nil {
			f.Write(append(line, '\n'))
		}
	}
}

// --- the loader of the boot -------------------------------------------

// errNoVerdict means the check could not run, which says nothing about the
// files. The guard then leaves everything as it is.
var errNoVerdict = errors.New("could not ask kairos-agent")

// agentLoads asks kairos-agent to load the files, with the loader it uses at
// boot and in strict mode, for a stage that has no step. nil means every file
// loads. A *loadError means at least one does not.
func (e configEnv) agentLoads(paths []string) error {
	if err := os.MkdirAll(e.real(e.Tmp), 0o700); err != nil {
		return fmt.Errorf("%w: %v", errNoVerdict, err)
	}
	dir, err := os.MkdirTemp(e.real(e.Tmp), "config-check-")
	if err != nil {
		return fmt.Errorf("%w: %v", errNoVerdict, err)
	}
	defer os.RemoveAll(dir)
	for i, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return fmt.Errorf("%w: %v", errNoVerdict, err)
		}
		name := fmt.Sprintf("%04d_%s", i, filepath.Base(p))
		if ext := filepath.Ext(name); ext != ".yaml" && ext != ".yml" {
			name += ".yaml"
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			return fmt.Errorf("%w: %v", errNoVerdict, err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, kairosAgent(), "run-stage", "--strict",
		"--override-cloud-init-paths", dir, configCheckStage)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	var exit *exec.ExitError
	if ctx.Err() != nil || !errors.As(err, &exit) {
		return fmt.Errorf("%w: %v", errNoVerdict, err)
	}
	return &loadError{Detail: loadDetail(string(out))}
}

type loadError struct{ Detail string }

func (l *loadError) Error() string {
	if l.Detail == "" {
		return "kairos-agent cannot load it"
	}
	return l.Detail
}

// loadDetail takes the reasons out of what kairos-agent printed. It lists
// them as "* reason" lines, once per stage it tried.
func loadDetail(out string) string {
	var reasons []string
	seen := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "* ") {
			continue
		}
		r := strings.TrimSpace(strings.TrimPrefix(line, "* "))
		if i := strings.Index(r, "\x1b"); i >= 0 {
			r = r[:i]
		}
		if r != "" && !seen[r] {
			seen[r] = true
			reasons = append(reasons, r)
		}
	}
	return strings.Join(reasons, "; ")
}

// badFiles returns the files kairos-agent will not load at boot, with the
// reason. It asks once for all of them, and file by file only when that
// fails, so a good config costs one call.
func (e configEnv) badFiles(files []configFile) (map[string]string, error) {
	if len(files) == 0 {
		return nil, nil
	}
	paths := make([]string, len(files))
	for i, f := range files {
		paths[i] = e.real(f.Path)
	}
	err := e.agentLoads(paths)
	if err == nil {
		return nil, nil
	}
	var le *loadError
	if !errors.As(err, &le) {
		return nil, err
	}
	bad := map[string]string{}
	for i, f := range files {
		err := e.agentLoads(paths[i : i+1])
		if err == nil {
			continue
		}
		if !errors.As(err, &le) {
			return nil, err
		}
		bad[f.Path] = le.Error()
	}
	if len(bad) == 0 {
		// All together fail and each alone loads: not a verdict on any file.
		return nil, fmt.Errorf("%w: the files load one by one but not together", errNoVerdict)
	}
	return bad, nil
}

// merged asks kairos-agent for the merged config, which follows config_url.
// It returns the hash of the config and what was merged.
func (e configEnv) merged() (string, []string) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, kairosAgent(), "config").Output()
	if err != nil {
		return "", nil
	}
	var sources []string
	var body bytes.Buffer
	inSources := false
	for _, line := range strings.SplitAfter(string(out), "\n") {
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(t, "# Sources:"):
			inSources = true
			continue
		case inSources && strings.HasPrefix(t, "# - "):
			sources = append(sources, redactURL(strings.TrimPrefix(t, "# - ")))
			continue
		case inSources && t == "#":
			continue
		}
		inSources = false
		body.WriteString(line)
	}
	sum := sha256.Sum256(body.Bytes())
	return hex.EncodeToString(sum[:]), sources
}

// redactURL drops what can hold a secret from a URL: the password and the
// query. A file path is returned as it is.
func redactURL(s string) string {
	if !strings.Contains(s, "://") {
		return s
	}
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	scheme, rest, _ := strings.Cut(s, "://")
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		if slash := strings.Index(rest, "/"); slash < 0 || at < slash {
			rest = rest[at+1:]
		}
	}
	return scheme + "://" + rest
}

// --- who can log in ----------------------------------------------------

// canLogin reports whether /etc/passwd has a person who can log in: a user
// id of a person and a shell that is a program. Kairos writes /etc/passwd
// again on every boot from the cloud-config, so this is the test of whether
// the config still creates the user.
func (e configEnv) canLogin() bool {
	data, err := os.ReadFile(e.real(e.Passwd))
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 7 {
			continue
		}
		uid, err := strconv.Atoi(f[2])
		if err != nil || uid < 1000 || uid >= 60000 {
			continue
		}
		shell := strings.TrimSpace(f[6])
		switch filepath.Base(shell) {
		case "", "nologin", "false":
			continue
		}
		if info, err := os.Stat(e.real(shell)); err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
			return true
		}
	}
	return false
}

// --- guard and commit --------------------------------------------------

// guard runs early in the boot, before Kairos reads /oem. It puts back the
// last good copy of each file that no longer loads. It never fails the boot:
// when it cannot tell, it changes nothing.
func (e configEnv) guard() []guardEvent {
	now := e.Now().UTC().Truncate(time.Second)
	files, err := e.scan()
	if err != nil {
		return []guardEvent{{Time: now, Stage: "guard", Action: "skipped", Reason: err.Error()}}
	}
	bad, err := e.badFiles(writable(files))
	if err != nil {
		return []guardEvent{{Time: now, Stage: "guard", Action: "skipped", Reason: err.Error()}}
	}
	if len(bad) == 0 {
		return nil
	}
	last := e.latest()
	good := map[string]configFile{}
	if last != nil {
		good = byPath(writable(last.Files))
	}
	stamp := now.Format("20060102-150405")
	paths := make([]string, 0, len(bad))
	for p := range bad {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	cur := byPath(files)
	var events []guardEvent
	for _, p := range paths {
		ev := guardEvent{Time: now, Stage: "guard", Path: p, Reason: bad[p]}
		g, ok := good[p]
		switch {
		case !ok:
			ev.Action = "left"
			ev.Reason += " (no earlier copy of this file; Kairos skips it)"
		case g.SHA256 == cur[p].SHA256:
			ev.Action = "left"
			ev.Reason += " (the last good copy is the same file)"
		default:
			saved, err := e.setAside(p, stamp)
			if err == nil {
				err = e.restoreFile(g)
			}
			if err != nil {
				ev.Action = "left"
				ev.Reason += " (could not restore: " + err.Error() + ")"
			} else {
				ev.Action = "restored"
				ev.Saved = saved
				ev.Reason += fmt.Sprintf(" (generation %d put back)", last.ID)
			}
		}
		events = append(events, ev)
	}
	return events
}

// commit runs after the boot stage. A boot that left a user who can log in
// becomes the new last good generation. A boot that left none, when the last
// good one had a user, goes back to that generation and runs the boot stage
// of the restored files again.
func (e configEnv) commit() ([]guardEvent, *generation, error) {
	now := e.Now().UTC().Truncate(time.Second)
	files, err := e.scan()
	if err != nil {
		return nil, nil, err
	}
	last := e.latest()
	login := e.canLogin()
	var events []guardEvent

	if !login && last != nil && last.Login {
		if fingerprint(writable(files)) == fingerprint(writable(last.Files)) {
			return []guardEvent{{Time: now, Stage: "commit", Action: "left",
				Reason: "no user can log in, and the config is the last good one; the cause is not a config file"}}, nil, nil
		}
		events, err = e.restoreSet(last, "commit")
		if err != nil {
			return events, nil, err
		}
		args := []string{"run-stage"}
		for _, d := range e.Dirs {
			if d.Writable {
				args = append(args, "--override-cloud-init-paths", e.real(d.Path))
			}
		}
		exec.Command(kairosAgent(), append(args, "boot")...).Run()
		reason := "no user could log in with the changed config"
		if e.canLogin() {
			reason += "; the user is back, restart to apply the rest"
		} else {
			reason += "; restart to apply the restored config"
		}
		events = append(events, guardEvent{Time: now, Stage: "commit", Action: "rolled back", Reason: reason})
		return events, nil, nil
	}

	if last != nil && last.Fingerprint == fingerprint(files) {
		return nil, nil, nil
	}
	bad, err := e.badFiles(writable(files))
	if err != nil && !errors.Is(err, errNoVerdict) {
		return nil, nil, err
	}
	if len(bad) > 0 {
		for p, r := range bad {
			events = append(events, guardEvent{Time: now, Stage: "commit", Path: p, Action: "not committed", Reason: r})
		}
		sort.Slice(events, func(i, j int) bool { return events[i].Path < events[j].Path })
		return events, nil, nil
	}
	merged, sources := e.merged()
	g, err := e.save(files, "boot", login, merged, sources)
	return nil, g, err
}
