package checks

import "github.com/TyrusRC/groma/internal/discovery"

// ObservationsFromBanners converts native TCP-connect scan results into
// Observations by fingerprinting banners against known service patterns
// (modeled after nmap service probes). This is the native-scanner
// counterpart to ObservationsFromNaabu — it gives the YAML CVE engine
// something to match against even when naabu is not installed.
func ObservationsFromBanners(host string, results []discovery.PortResult) []Observation {
	out := make([]Observation, 0, len(results))
	for _, r := range results {
		if !r.Open {
			continue
		}
		si := discovery.FingerprintBanner(r.Banner)
		if si == nil {
			continue
		}
		if si.Product == "" && len(si.CPEs) == 0 {
			continue
		}
		out = append(out, Observation{
			Host:     host,
			Port:     r.Port,
			Protocol: "tcp",
			Product:  si.Product,
			Version:  si.Version,
			CPEs:     si.CPEs,
		})
	}
	return out
}
