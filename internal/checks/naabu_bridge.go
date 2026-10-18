package checks

import "github.com/TyrusRC/groma/internal/tools/naabu"

// ObservationsFromNaabu converts naabu's port-scan results into the
// neutral Observation shape this package matches against. Kept as its
// own small file so a future second source of service data (a banner
// heuristic, a different scanner) is a sibling file, not a change to
// check.go's matching logic.
func ObservationsFromNaabu(host string, results []naabu.Result) []Observation {
	out := make([]Observation, 0, len(results))
	for _, r := range results {
		if r.Product == "" && len(r.CPEs) == 0 {
			continue // nothing for a service-match check to match against
		}
		out = append(out, Observation{
			Host:     host,
			Port:     r.Port,
			Protocol: r.Protocol,
			Product:  r.Product,
			Version:  r.Version,
			CPEs:     r.CPEs,
		})
	}
	return out
}
