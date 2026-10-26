package checks

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadChecks reads every .yaml/.yml file under dir (recursively) and
// parses it as a Check. A malformed file is a hard error — a check that
// fails to load silently is a check that never runs, which is worse
// than refusing to start.
func LoadChecks(dir string) ([]*Check, error) {
	return LoadChecksFS(os.DirFS(dir), ".")
}

// LoadChecksFS is LoadChecks over any fs.FS, so the bundled checks can be
// parsed straight from an embed.FS with no files on disk (see the root
// checks package). root is the directory within fsys to walk.
func LoadChecksFS(fsys fs.FS, root string) ([]*Check, error) {
	var out []*Check
	err := fs.WalkDir(fsys, root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		data, readErr := fs.ReadFile(fsys, path)
		if readErr != nil {
			return fmt.Errorf("%s: %w", path, readErr)
		}
		c, loadErr := parseCheck(data)
		if loadErr != nil {
			return fmt.Errorf("%s: %w", path, loadErr)
		}
		out = append(out, c)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func parseCheck(data []byte) (*Check, error) {
	var c Check
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	if c.ID == "" {
		return nil, fmt.Errorf("missing required field: id")
	}
	if c.Info.Name == "" {
		return nil, fmt.Errorf("missing required field: info.name")
	}
	if !c.Info.Severity.IsValid() {
		return nil, fmt.Errorf("invalid or missing info.severity: %q", c.Info.Severity)
	}
	if c.Service.Product == "" && c.Service.CPE == "" {
		return nil, fmt.Errorf("service.product or service.cpe is required (a check with neither can never match)")
	}
	return &c, nil
}
