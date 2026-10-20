package checks

import "github.com/TyrusRC/groma/internal/discovery"

// ObservationsFromProbes converts active probe results into Observations
// for the YAML CVE check engine. This is the bridge between the native
// active prober (discovery.ProbeResults) and the check engine.
func ObservationsFromProbes(host string, results []discovery.PortResult, svcMap map[int]*discovery.ServiceInfo) []Observation {
	out := make([]Observation, 0, len(svcMap))
	for _, r := range results {
		if !r.Open {
			continue
		}
		si, ok := svcMap[r.Port]
		if !ok || si == nil {
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
