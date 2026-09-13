// Copyright 2026 Thingz LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package cli

// Severity vocabulary shared by --min-severity, --fail-on, and the per-severity
// --max-* gates. The names are the ones the DevRadar API accepts.
const (
	sevCritical   = "critical"
	sevHigh       = "high"
	sevMedium     = "medium"
	sevLow        = "low"
	sevNegligible = "negligible"
)

// severityOrder lists them most severe first, and is the single source both
// derived tables below are built from. Keeping the ordering used by --fail-on
// and the set accepted by --min-severity in one place is what stops them
// drifting apart: a severity added to one but not the other is the kind of gap
// that makes a CI gate silently accept what it was meant to reject.
var severityOrder = []string{sevCritical, sevHigh, sevMedium, sevLow, sevNegligible}

// severityRank orders severities for the --fail-on floor comparison. Higher is
// more severe; an unknown or unrecognized severity sorts below negligible.
var severityRank = func() map[string]int {
	m := make(map[string]int, len(severityOrder))
	for i, s := range severityOrder {
		m[s] = len(severityOrder) - i
	}
	return m
}()

// validSeverities is the set the API accepts for min_severity / fail-on floors.
var validSeverities = func() map[string]bool {
	m := make(map[string]bool, len(severityOrder))
	for _, s := range severityOrder {
		m[s] = true
	}
	return m
}()

// argsSBOMID is the ArgsUsage string every per-SBOM read subcommand shows.
const argsSBOMID = "<sbom-id>"
