package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const configUsage = `Usage: isotope config [command]

The cloud-config files of this machine: what Kairos applies on every boot
from /system/oem, /oem and /usr/local/cloud-config. Runs as root through sudo.

Commands:
  status            the fingerprint of the config, the last good generation,
                    what changed since, and what the last boot repaired
                    (default)
      --json             the same as JSON
      --remote           also the merged config, which follows config_url
  check [FILE...]   load each file the way the boot does and say which ones
                    Kairos would skip; exits 1 when one does not load, 3
                    when kairos-agent gave no answer.
                    Without FILE: every file of this machine
  apply FILE        check FILE, then install it in /oem under its own name;
                    a file that does not load is refused
      --as NAME          install it as /oem/NAME
  diff [GEN]        what changed since generation GEN (default: the last)
  history           the generations kept on this machine
  rollback [GEN]    put the files of generation GEN back (default: the last
                    good one, or the one before when nothing changed since).
                    The files it replaces are kept; restart to apply
      --yes              do not ask for confirmation
  help              this text

Started by the boot, not by hand:
  guard             before Kairos reads /oem: put back the last good copy of
                    a file that no longer loads
  commit            after the boot: record a new generation, or go back to the
                    last one when no user can log in

A generation is the config of a boot that ended with a user who can log in.
The last ` + "5" + ` are kept in /oem/.isotope-config.
`

func cmdConfig(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	cmd := "status"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	e := newConfigEnv()
	switch cmd {
	case "status":
		return configStatus(e, args, stdout, stderr)
	case "check":
		return configCheck(e, args, stdout, stderr)
	case "apply":
		return configApply(e, args, stdout, stderr)
	case "diff":
		return configDiff(e, args, stdout, stderr)
	case "history":
		return configHistory(e, stdout)
	case "rollback":
		return configRollback(e, args, stdin, stdout, stderr)
	case "guard":
		// Never fail the boot: the guard reports, it does not stop anything.
		// Never hold it up either: the initramfs waits for this.
		e.Until = time.Now().Add(90 * time.Second)
		unlock, err := e.lock()
		if err != nil {
			fmt.Fprintf(stderr, "isotope config guard: %v\n", err)
			return exitOK
		}
		defer unlock()
		events := e.guard()
		e.record(events)
		printEvents(stderr, events)
		return exitOK
	case "commit":
		// The unit has 5 minutes (TimeoutStartSec).
		e.Until = time.Now().Add(4 * time.Minute)
		unlock, err := e.lock()
		if err != nil {
			return configFail(stderr, err)
		}
		defer unlock()
		events, g, err := e.commit()
		e.record(events)
		printEvents(stderr, events)
		if err != nil {
			fmt.Fprintf(stderr, "isotope config: %v\n", err)
			return exitError
		}
		if g != nil {
			fmt.Fprintf(stdout, "generation %d recorded, fingerprint %s\n", g.ID, short(g.Fingerprint))
		}
		return exitOK
	case "help", "-h", "--help":
		fmt.Fprint(stdout, configUsage)
		return exitOK
	default:
		fmt.Fprintf(stderr, "isotope config: unknown command %q\n\n%s", cmd, configUsage)
		return exitUsage
	}
}

func short(sum string) string {
	if len(sum) > 12 {
		return sum[:12]
	}
	return sum
}

func printEvents(w io.Writer, events []guardEvent) {
	for _, ev := range events {
		line := "isotope config " + ev.Stage + ": " + ev.Action
		if ev.Path != "" {
			line += " " + ev.Path
		}
		if ev.Reason != "" {
			line += ": " + ev.Reason
		}
		if ev.Saved != "" {
			line += "; the replaced file is " + ev.Saved
		}
		fmt.Fprintln(w, line)
	}
}

// exitNoVerdict is for a check kairos-agent did not answer: not "the file is
// bad", and not "the file is good".
const exitNoVerdict = 3

func configFail(stderr io.Writer, err error) int {
	if errors.Is(err, os.ErrPermission) {
		fmt.Fprintf(stderr, "isotope config: %v\nThe cloud-config files belong to root: run it with sudo.\n", err)
	} else {
		fmt.Fprintf(stderr, "isotope config: %v\n", err)
	}
	if errors.Is(err, errNoVerdict) {
		return exitNoVerdict
	}
	return exitError
}

// flagsFirst moves the flags before the other arguments, so that
// "rollback 3 --yes" is "rollback --yes 3". None of these flags takes a value
// but --as.
func flagsFirst(args []string) []string {
	var flags, rest []string
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--as" || args[i] == "-as":
			flags = append(flags, args[i])
			if i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
		case strings.HasPrefix(args[i], "-") && args[i] != "-":
			flags = append(flags, args[i])
		default:
			rest = append(rest, args[i])
		}
	}
	return append(flags, rest...)
}

// change is one file that differs between a generation and the disk.
type change struct {
	Path   string `json:"path"`
	Change string `json:"change"` // added, changed, removed
	Image  bool   `json:"image,omitempty"`
}

func changes(old, cur []configFile) []change {
	o, c := byPath(old), byPath(cur)
	var out []change
	for p, f := range c {
		if prev, ok := o[p]; !ok {
			out = append(out, change{p, "added", !f.Writable})
		} else if prev.SHA256 != f.SHA256 {
			out = append(out, change{p, "changed", !f.Writable})
		}
	}
	for p, f := range o {
		if _, ok := c[p]; !ok {
			out = append(out, change{p, "removed", !f.Writable})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

type statusReport struct {
	Fingerprint string       `json:"fingerprint"`
	State       string       `json:"state"` // committed, changed, new
	Generation  int          `json:"generation,omitempty"`
	Committed   string       `json:"committed,omitempty"`
	Changes     []change     `json:"changes,omitempty"`
	Events      []guardEvent `json:"events,omitempty"`
	Files       []configFile `json:"files"`
	Merged      string       `json:"merged,omitempty"`
	MergedState string       `json:"merged_state,omitempty"`
	Sources     []string     `json:"sources,omitempty"`
	Missing     []string     `json:"sources_missing,omitempty"`
}

func configStatus(e configEnv, args []string, stdout, stderr io.Writer) int {
	fs := newFlags("config status", stderr)
	asJSON := fs.Bool("json", false, "")
	remote := fs.Bool("remote", false, "")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	files, err := e.scan()
	if err != nil {
		return configFail(stderr, err)
	}
	r := statusReport{Fingerprint: fingerprint(files), State: "new", Files: files, Events: e.events()}
	last := e.latest()
	if last != nil {
		r.Generation, r.Committed = last.ID, last.Time.Format("2006-01-02 15:04 UTC")
		r.State = "committed"
		if last.Fingerprint != r.Fingerprint {
			r.State = "changed"
			r.Changes = changes(last.Files, files)
		}
	}
	if *remote {
		r.Merged, r.Sources = e.merged()
		if last != nil && last.Merged != "" && r.Merged != "" {
			r.MergedState = "same"
			if last.Merged != r.Merged {
				r.MergedState = "changed"
			}
			have := map[string]bool{}
			for _, s := range r.Sources {
				have[s] = true
			}
			for _, s := range last.Sources {
				if !have[s] {
					r.Missing = append(r.Missing, s)
				}
			}
		}
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
		return exitOK
	}
	fmt.Fprintf(stdout, "Fingerprint  %s  (%d files)\n", short(r.Fingerprint), len(files))
	switch r.State {
	case "new":
		fmt.Fprintln(stdout, "State        no generation yet; the next good boot records the first one")
	case "committed":
		fmt.Fprintf(stdout, "State        the same as generation %d, a good boot of %s\n", r.Generation, r.Committed)
	case "changed":
		fmt.Fprintf(stdout, "State        changed since generation %d (%s); not yet proven by a boot\n", r.Generation, r.Committed)
		for _, c := range r.Changes {
			note := ""
			if c.Image {
				note = "  (part of the system image)"
			}
			fmt.Fprintf(stdout, "  %-8s %s%s\n", c.Change, c.Path, note)
		}
	}
	if *remote {
		switch {
		case r.Merged == "":
			fmt.Fprintln(stdout, "Merged       kairos-agent did not print the merged config")
		case r.MergedState == "":
			fmt.Fprintf(stdout, "Merged       %s\n", short(r.Merged))
		default:
			fmt.Fprintf(stdout, "Merged       %s  (%s since generation %d)\n", short(r.Merged), r.MergedState, r.Generation)
		}
		for _, s := range r.Missing {
			fmt.Fprintf(stdout, "  not read now, read at generation %d: %s\n", r.Generation, s)
		}
	}
	if len(r.Events) > 0 {
		fmt.Fprintln(stdout, "\nThe last boot:")
		for _, ev := range r.Events {
			fmt.Fprintf(stdout, "  %s %s", ev.Action, ev.Path)
			if ev.Reason != "" {
				fmt.Fprintf(stdout, ": %s", ev.Reason)
			}
			fmt.Fprintln(stdout)
			if ev.Saved != "" {
				fmt.Fprintf(stdout, "    the replaced file is %s\n", ev.Saved)
			}
		}
	}
	return exitOK
}

func configCheck(e configEnv, args []string, stdout, stderr io.Writer) int {
	var files []configFile
	bad := map[string]string{}
	if len(args) == 0 {
		all, err := e.scan()
		if err != nil {
			return configFail(stderr, err)
		}
		files = all
		if bad, err = e.badFiles(files); err != nil {
			return configFail(stderr, err)
		}
	}
	for _, a := range args {
		abs, err := filepath.Abs(a)
		if err != nil {
			return configFail(stderr, err)
		}
		files = append(files, configFile{Path: a})
		if _, err := os.Stat(abs); err != nil {
			return configFail(stderr, err)
		}
		reason, err := e.badFile(abs)
		if err != nil {
			return configFail(stderr, err)
		}
		if reason != "" {
			bad[a] = reason
		}
	}
	for _, f := range files {
		if reason, ok := bad[f.Path]; ok {
			fmt.Fprintf(stdout, "BAD  %s\n     %s\n", f.Path, reason)
		} else {
			fmt.Fprintf(stdout, "ok   %s\n", f.Path)
		}
	}
	if len(bad) > 0 {
		fmt.Fprintf(stdout, "\nKairos skips a file that does not load, with everything in it: its users are not created.\n")
		return exitError
	}
	return exitOK
}

func configApply(e configEnv, args []string, stdout, stderr io.Writer) int {
	fs := newFlags("config apply", stderr)
	as := fs.String("as", "", "")
	if err := fs.Parse(flagsFirst(args)); err != nil || fs.NArg() != 1 {
		fmt.Fprint(stderr, "isotope config apply: give one FILE\n")
		return exitUsage
	}
	src := fs.Arg(0)
	name := *as
	if name == "" {
		name = filepath.Base(src)
	}
	if name != filepath.Base(name) || (filepath.Ext(name) != ".yaml" && filepath.Ext(name) != ".yml") {
		fmt.Fprintf(stderr, "isotope config apply: %q is not a file name that ends in .yaml\n", name)
		return exitUsage
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return configFail(stderr, err)
	}
	unlock, err := e.lock()
	if err != nil {
		return configFail(stderr, err)
	}
	defer unlock()
	// Check the bytes that get installed, not the file a second time.
	if err := os.MkdirAll(e.real(e.Tmp), 0o700); err != nil {
		return configFail(stderr, err)
	}
	cand, err := os.CreateTemp(e.real(e.Tmp), "config-apply-")
	if err != nil {
		return configFail(stderr, err)
	}
	defer os.Remove(cand.Name())
	_, err = cand.Write(data)
	if cerr := cand.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return configFail(stderr, err)
	}
	reason, err := e.badFile(cand.Name())
	if err != nil {
		return configFail(stderr, err)
	}
	if reason != "" {
		fmt.Fprintf(stderr, "isotope config apply: %s does not load, nothing was changed:\n  %s\n", src, reason)
		return exitError
	}
	dst := filepath.Join("/oem", name)
	mode, uid, gid, saved := os.FileMode(0o600), -1, -1, ""
	if info, err := os.Stat(e.real(dst)); err == nil {
		mode = info.Mode().Perm()
		uid, gid = owner(info)
		if saved, err = e.setAside(dst, e.Now().UTC().Format("20060102-150405")); err != nil {
			return configFail(stderr, err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(e.real(dst)), 0o755); err != nil {
		return configFail(stderr, err)
	}
	if err := writeAtomic(e.real(dst), data, mode); err != nil {
		return configFail(stderr, err)
	}
	if uid >= 0 {
		os.Chown(e.real(dst), uid, gid)
	}
	fmt.Fprintf(stdout, "%s installed. It applies at the next boot.\n", dst)
	if saved != "" {
		fmt.Fprintf(stdout, "The file it replaced is %s.\n", saved)
	}
	if l := e.latest(); l != nil {
		fmt.Fprintf(stdout, "\"isotope config rollback\" goes back to generation %d.\n", l.ID)
	}
	return exitOK
}

func (e configEnv) pick(arg string) (*generation, error) {
	gens := e.generations()
	if len(gens) == 0 {
		return nil, errors.New("no generation yet; the first good boot records one")
	}
	if arg == "" {
		return &gens[len(gens)-1], nil
	}
	id, err := strconv.Atoi(arg)
	if err != nil {
		return nil, fmt.Errorf("%q is not a generation number", arg)
	}
	for i := range gens {
		if gens[i].ID == id {
			return &gens[i], nil
		}
	}
	return nil, fmt.Errorf("no generation %d; see \"isotope config history\"", id)
}

func configDiff(e configEnv, args []string, stdout, stderr io.Writer) int {
	arg := ""
	if len(args) > 0 {
		arg = args[0]
	}
	g, err := e.pick(arg)
	if err != nil {
		return configFail(stderr, err)
	}
	files, err := e.scan()
	if err != nil {
		return configFail(stderr, err)
	}
	ch := changes(g.Files, files)
	if len(ch) == 0 {
		fmt.Fprintf(stdout, "No change since generation %d.\n", g.ID)
		return exitOK
	}
	old := byPath(g.Files)
	for _, c := range ch {
		fmt.Fprintf(stdout, "%s %s\n", c.Change, c.Path)
		if c.Image {
			fmt.Fprintln(stdout, "  (part of the system image: it changed with an upgrade)")
			continue
		}
		var a, b []byte
		if c.Change != "added" {
			if a, err = os.ReadFile(e.blob(old[c.Path].SHA256)); err != nil {
				fmt.Fprintf(stdout, "  (the kept copy cannot be read: %v)\n", err)
				continue
			}
		}
		if c.Change != "removed" {
			if b, err = os.ReadFile(e.real(c.Path)); err != nil {
				return configFail(stderr, err)
			}
		}
		for _, l := range lineDiff(string(a), string(b)) {
			fmt.Fprintln(stdout, "  "+l)
		}
	}
	return exitOK
}

// lineDiff is the lines that differ, "-" for a's and "+" for b's, each with
// its line number. Config files are small, so the plain table is enough.
func lineDiff(a, b string) []string {
	x, y := splitLines(a), splitLines(b)
	lcs := make([][]int, len(x)+1)
	for i := range lcs {
		lcs[i] = make([]int, len(y)+1)
	}
	for i := len(x) - 1; i >= 0; i-- {
		for j := len(y) - 1; j >= 0; j-- {
			if x[i] == y[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	var out []string
	i, j := 0, 0
	for i < len(x) || j < len(y) {
		switch {
		case i < len(x) && j < len(y) && x[i] == y[j]:
			i, j = i+1, j+1
		case i < len(x) && (j == len(y) || lcs[i+1][j] >= lcs[i][j+1]):
			out = append(out, fmt.Sprintf("-%4d  %s", i+1, x[i]))
			i++
		default:
			out = append(out, fmt.Sprintf("+%4d  %s", j+1, y[j]))
			j++
		}
	}
	return out
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}

func configHistory(e configEnv, stdout io.Writer) int {
	gens := e.generations()
	if len(gens) == 0 {
		fmt.Fprintln(stdout, "No generation yet; the first good boot records one.")
		return exitOK
	}
	for i := len(gens) - 1; i >= 0; i-- {
		g := gens[i]
		what := "the first one"
		if i > 0 {
			var parts []string
			for _, c := range changes(gens[i-1].Files, g.Files) {
				parts = append(parts, c.Change+" "+c.Path)
			}
			what = strings.Join(parts, ", ")
		}
		fmt.Fprintf(stdout, "%4d  %s  %s  %s\n", g.ID, g.Time.Format("2006-01-02 15:04 UTC"), short(g.Fingerprint), what)
	}
	return exitOK
}

func configRollback(e configEnv, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := newFlags("config rollback", stderr)
	yes := fs.Bool("yes", false, "")
	if err := fs.Parse(flagsFirst(args)); err != nil || fs.NArg() > 1 {
		fmt.Fprint(stderr, "isotope config rollback: give at most one generation\n")
		return exitUsage
	}
	unlock, err := e.lock()
	if err != nil {
		return configFail(stderr, err)
	}
	defer unlock()
	files, err := e.scan()
	if err != nil {
		return configFail(stderr, err)
	}
	g, err := e.pick(fs.Arg(0))
	if err != nil {
		return configFail(stderr, err)
	}
	if fs.Arg(0) == "" && fingerprint(writable(g.Files)) == fingerprint(writable(files)) {
		// Nothing changed since the last good boot: go one further back.
		gens := e.generations()
		if len(gens) < 2 {
			fmt.Fprintf(stdout, "The config is generation %d already, and there is none before it.\n", g.ID)
			return exitOK
		}
		g = &gens[len(gens)-2]
	}
	ch := changes(writable(files), writable(g.Files))
	if len(ch) == 0 {
		fmt.Fprintf(stdout, "The config is generation %d already.\n", g.ID)
		return exitOK
	}
	fmt.Fprintf(stdout, "Going back to generation %d (%s):\n", g.ID, g.Time.Format("2006-01-02 15:04 UTC"))
	for _, c := range ch {
		// Seen from the disk: a file "added" by the generation is one to put back.
		verb := map[string]string{"added": "put back", "changed": "replace", "removed": "remove"}[c.Change]
		fmt.Fprintf(stdout, "  %-8s %s\n", verb, c.Path)
	}
	if !*yes && !confirm(bufio.NewReader(stdin), stdout, "Continue?", false) {
		fmt.Fprintln(stdout, "Nothing was changed.")
		return exitError
	}
	events, err := e.restoreSet(g, "rollback")
	e.record(events)
	if err != nil {
		return configFail(stderr, err)
	}
	fmt.Fprintf(stdout, "Done. The files it replaced are in %s/rejected. Restart to apply.\n", e.State)
	return exitOK
}
