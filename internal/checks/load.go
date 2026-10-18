package checks

import (
	"fmt"
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
	var out []*Check
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
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
		c, loadErr := loadCheckFile(path)
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

func loadCheckFile(path string) (*Check, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
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
