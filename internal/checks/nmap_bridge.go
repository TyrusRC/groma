package checks

import nmaptool "github.com/TyrusRC/groma/internal/tools/nmap"

// ObservationsFromNmap converts nmap's scan results into Observations
// for the YAML CVE check engine — the same shape as ObservationsFromNaabu.
func ObservationsFromNmap(host string, results []nmaptool.Result) []Observation {
	out := make([]Observation, 0, len(results))
	for _, r := range results {
		if r.Product == "" && len(r.CPEs) == 0 {
			continue
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
