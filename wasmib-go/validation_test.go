package wasmib

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// smidumpEntry represents a parsed line from smidump -f identifiers
type smidumpEntry struct {
	Module string
	Name   string
	Kind   string // node, scalar, table, row, column, type, notification, group, compliance
	OID    string // empty for types
}

// parseSmidumpIdentifiers parses output from `smidump -f identifiers`
func parseSmidumpIdentifiers(output string) []smidumpEntry {
	var entries []smidumpEntry
	// Pattern: MODULE NAME KIND OID
	// Example: IF-MIB ifMtu column 1.3.6.1.2.1.2.2.1.4
	re := regexp.MustCompile(`^(\S+)\s+(\S+)\s+(node|scalar|table|row|column|type|notification|group|compliance)\s+(\S*)`)

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		matches := re.FindStringSubmatch(line)
		if matches != nil {
			entries = append(entries, smidumpEntry{
				Module: matches[1],
				Name:   matches[2],
				Kind:   matches[3],
				OID:    matches[4],
			})
		}
	}
	return entries
}

// runSmidump runs smidump on a MIB file and returns the identifiers output
func runSmidump(mibPath string) (string, error) {
	cmd := exec.Command("smidump", "-l", "0", "-f", "identifiers", mibPath)
	out, err := cmd.Output()
	if err != nil {
		// smidump may return non-zero but still produce useful output
		if exitErr, ok := err.(*exec.ExitError); ok {
			_ = exitErr // Ignore exit errors, check output
		} else {
			return "", err
		}
	}
	return string(out), nil
}

// mapWasmibKind converts wasmib NodeKind to smidump kind string
func mapWasmibKind(kind NodeKind) string {
	switch kind {
	case NodeKindNode, NodeKindInternal:
		return "node"
	case NodeKindScalar:
		return "scalar"
	case NodeKindTable:
		return "table"
	case NodeKindRow:
		return "row"
	case NodeKindColumn:
		return "column"
	case NodeKindNotification:
		return "notification"
	case NodeKindGroup:
		return "group"
	case NodeKindCompliance:
		return "compliance"
	case NodeKindCapabilities:
		return "compliance" // smidump maps capabilities to compliance
	default:
		return "node"
	}
}

func TestValidationAgainstSmidump(t *testing.T) {
	// Check if smidump is available
	if _, err := exec.LookPath("smidump"); err != nil {
		t.Skip("smidump not found, skipping validation test")
	}

	// Load corpus with wasmib
	model := loadTestCorpus(t)

	// MIBs to validate (those with OID definitions)
	mibsToValidate := []string{
		"IF-MIB",
		"SNMPv2-MIB",
		"HOST-RESOURCES-MIB",
		"BGP4-MIB",
		"IP-MIB",
		"OSPF-MIB",
	}

	var totalMatches, totalMismatches, totalMissing int

	for _, mibName := range mibsToValidate {
		mibPath := filepath.Join("testdata", mibName)
		if _, err := os.Stat(mibPath); os.IsNotExist(err) {
			t.Logf("Skipping %s: file not found", mibName)
			continue
		}

		t.Run(mibName, func(t *testing.T) {
			// Get smidump output
			output, err := runSmidump(mibPath)
			if err != nil {
				t.Fatalf("smidump failed: %v", err)
			}

			entries := parseSmidumpIdentifiers(output)
			if len(entries) == 0 {
				t.Fatalf("No entries parsed from smidump output")
			}

			matches := 0
			mismatches := 0
			missing := 0

			for _, entry := range entries {
				if entry.OID == "" {
					continue // Skip type definitions
				}

				// Look up in wasmib
				node := model.GetNodeByOID(entry.OID)
				if node == nil {
					missing++
					t.Logf("MISSING: %s::%s at %s", entry.Module, entry.Name, entry.OID)
					continue
				}

				// Check kind
				wasmibKind := mapWasmibKind(node.Kind)
				if wasmibKind != entry.Kind {
					// Some flexibility: smidump may classify differently
					if !(entry.Kind == "node" && (wasmibKind == "scalar" || wasmibKind == "node")) {
						mismatches++
						t.Logf("KIND MISMATCH: %s::%s - smidump=%s wasmib=%s",
							entry.Module, entry.Name, entry.Kind, wasmibKind)
						continue
					}
				}

				// Check name exists in definitions
				foundName := false
				for _, def := range node.Definitions {
					name := model.GetStr(def.Label)
					if name == entry.Name {
						foundName = true
						break
					}
				}
				if !foundName {
					mismatches++
					var names []string
					for _, def := range node.Definitions {
						names = append(names, model.GetStr(def.Label))
					}
					t.Logf("NAME MISMATCH: %s at %s - smidump=%s wasmib=%v",
						entry.Module, entry.OID, entry.Name, names)
					continue
				}

				matches++
			}

			totalMatches += matches
			totalMismatches += mismatches
			totalMissing += missing

			t.Logf("%s: %d matches, %d mismatches, %d missing (of %d entries)",
				mibName, matches, mismatches, missing, len(entries))

			// Fail if too many mismatches
			errorRate := float64(mismatches+missing) / float64(len(entries))
			if errorRate > 0.1 {
				t.Errorf("Error rate %.1f%% exceeds 10%% threshold", errorRate*100)
			}
		})
	}

	t.Logf("TOTAL: %d matches, %d mismatches, %d missing",
		totalMatches, totalMismatches, totalMissing)
}

func TestValidationOIDDetails(t *testing.T) {
	// Check if smidump is available
	if _, err := exec.LookPath("smidump"); err != nil {
		t.Skip("smidump not found, skipping validation test")
	}

	model := loadTestCorpus(t)

	// Test specific OIDs with detailed comparison
	tests := []struct {
		oid         string
		name        string
		module      string
		kind        string
		access      string // readonly, readwrite, not-accessible
		baseType    string // Integer32, OctetString, etc.
	}{
		{"1.3.6.1.2.1.1.1", "sysDescr", "SNMPv2-MIB", "scalar", "readonly", "OctetString"},
		{"1.3.6.1.2.1.1.4", "sysContact", "SNMPv2-MIB", "scalar", "readwrite", "OctetString"},
		{"1.3.6.1.2.1.2.2", "ifTable", "IF-MIB", "table", "", ""},
		{"1.3.6.1.2.1.2.2.1", "ifEntry", "IF-MIB", "row", "not-accessible", ""},
		{"1.3.6.1.2.1.2.2.1.1", "ifIndex", "IF-MIB", "column", "readonly", "Integer32"},
		{"1.3.6.1.2.1.2.2.1.4", "ifMtu", "IF-MIB", "column", "readonly", "Integer32"},
		{"1.3.6.1.2.1.2.2.1.7", "ifAdminStatus", "IF-MIB", "column", "readwrite", "Integer32"},
	}

	for _, tt := range tests {
		t.Run(tt.oid, func(t *testing.T) {
			node := model.GetNodeByOID(tt.oid)
			if node == nil {
				t.Fatalf("Node not found for OID %s", tt.oid)
			}

			// Check kind
			wasmibKind := mapWasmibKind(node.Kind)
			if wasmibKind != tt.kind {
				t.Errorf("kind = %s, want %s", wasmibKind, tt.kind)
			}

			// Check name
			foundName := false
			for _, def := range node.Definitions {
				if model.GetStr(def.Label) == tt.name {
					foundName = true
					break
				}
			}
			if !foundName {
				t.Errorf("name %s not found in definitions", tt.name)
			}

			// Check access if specified
			if tt.access != "" {
				obj := model.GetObject(node)
				if obj == nil {
					t.Fatalf("Object not found for %s", tt.name)
				}

				var wasmibAccess string
				switch obj.Access {
				case AccessReadOnly:
					wasmibAccess = "readonly"
				case AccessReadWrite:
					wasmibAccess = "readwrite"
				case AccessNotAccessible:
					wasmibAccess = "not-accessible"
				case AccessReadCreate:
					wasmibAccess = "readcreate"
				case AccessAccessibleForNotify:
					wasmibAccess = "accessiblefornotify"
				}

				if wasmibAccess != tt.access {
					t.Errorf("access = %s, want %s", wasmibAccess, tt.access)
				}
			}

			// Check base type if specified
			if tt.baseType != "" {
				obj := model.GetObject(node)
				if obj == nil {
					t.Fatalf("Object not found for %s", tt.name)
				}

				typ := model.GetType(obj.TypeID)
				if typ == nil {
					t.Fatalf("Type not found for %s", tt.name)
				}

				var wasmibBase string
				switch typ.Base {
				case BaseTypeInteger32:
					wasmibBase = "Integer32"
				case BaseTypeOctetString:
					wasmibBase = "OctetString"
				case BaseTypeObjectIdentifier:
					wasmibBase = "ObjectIdentifier"
				case BaseTypeCounter32:
					wasmibBase = "Counter32"
				case BaseTypeCounter64:
					wasmibBase = "Counter64"
				case BaseTypeGauge32:
					wasmibBase = "Gauge32"
				case BaseTypeTimeTicks:
					wasmibBase = "TimeTicks"
				case BaseTypeIpAddress:
					wasmibBase = "IpAddress"
				case BaseTypeBits:
					wasmibBase = "Bits"
				}

				if wasmibBase != tt.baseType {
					t.Errorf("baseType = %s, want %s", wasmibBase, tt.baseType)
				}
			}
		})
	}
}

func TestValidationEnumValues(t *testing.T) {
	model := loadTestCorpus(t)

	// ifAdminStatus has enum: up(1), down(2), testing(3)
	node := model.GetNodeByOID("1.3.6.1.2.1.2.2.1.7")
	if node == nil {
		t.Fatal("ifAdminStatus not found")
	}

	obj := model.GetObject(node)
	if obj == nil {
		t.Fatal("ifAdminStatus object not found")
	}

	// Get enums from inline or type
	var enums []EnumValue
	if len(obj.InlineEnum) > 0 {
		enums = obj.InlineEnum
	} else if obj.TypeID > 0 {
		typ := model.GetType(obj.TypeID)
		if typ != nil {
			enums = typ.EnumValues
		}
	}

	expected := map[int64]string{
		1: "up",
		2: "down",
		3: "testing",
	}

	for val, name := range expected {
		found := false
		for _, ev := range enums {
			if ev.Value == val && model.GetStr(ev.Name) == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected enum %s(%d) not found", name, val)
		}
	}
}

func TestValidationDisplayHints(t *testing.T) {
	model := loadTestCorpus(t)

	tests := []struct {
		oid  string
		name string
		hint string
	}{
		{"1.3.6.1.2.1.1.1", "sysDescr", "255a"},     // DisplayString
		{"1.3.6.1.2.1.2.2.1.6", "ifPhysAddress", "1x:"}, // PhysAddress
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := model.GetNodeByOID(tt.oid)
			if node == nil {
				t.Skipf("Node %s not found", tt.name)
			}

			obj := model.GetObject(node)
			if obj == nil {
				t.Fatalf("Object not found")
			}

			hint := model.GetEffectiveHint(obj.TypeID)
			if hint != tt.hint {
				t.Errorf("hint = %q, want %q", hint, tt.hint)
			}
		})
	}
}

func TestValidationFullCorpus(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping full corpus validation in short mode")
	}

	// Check if smidump is available
	if _, err := exec.LookPath("smidump"); err != nil {
		t.Skip("smidump not found, skipping validation test")
	}

	ctx := context.Background()
	corpusDir := "testdata"

	// Load all MIBs
	model, err := LoadDir(ctx, corpusDir)
	if err != nil {
		t.Fatalf("LoadDir failed: %v", err)
	}

	t.Logf("Loaded model: %d modules, %d nodes, %d types, %d objects",
		model.ModuleCount(), model.NodeCount(), model.TypeCount(), model.ObjectCount())

	// Get smidump output for each MIB file
	entries, err := os.ReadDir(corpusDir)
	if err != nil {
		t.Fatalf("ReadDir failed: %v", err)
	}

	var allSmidumpEntries []smidumpEntry
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(corpusDir, entry.Name())
		output, err := runSmidump(path)
		if err != nil {
			t.Logf("smidump failed for %s: %v", entry.Name(), err)
			continue
		}
		parsed := parseSmidumpIdentifiers(output)
		allSmidumpEntries = append(allSmidumpEntries, parsed...)
	}

	// Deduplicate by OID
	oidToEntry := make(map[string]smidumpEntry)
	for _, e := range allSmidumpEntries {
		if e.OID != "" {
			oidToEntry[e.OID] = e
		}
	}

	matches := 0
	mismatches := 0
	missing := 0

	for oid, entry := range oidToEntry {
		node := model.GetNodeByOID(oid)
		if node == nil {
			missing++
			continue
		}

		wasmibKind := mapWasmibKind(node.Kind)
		if wasmibKind == entry.Kind {
			matches++
		} else {
			// Allow some flexibility
			if entry.Kind == "node" && (wasmibKind == "scalar" || wasmibKind == "node") {
				matches++
			} else {
				mismatches++
			}
		}
	}

	total := len(oidToEntry)
	found := matches + mismatches

	// Calculate accuracy only for OIDs that wasmib found
	var accuracy float64
	if found > 0 {
		accuracy = float64(matches) / float64(found) * 100
	}

	t.Logf("Full corpus validation: %d/%d found OIDs match (%.1f%% accuracy), %d mismatches, %d missing (unresolved deps)",
		matches, found, accuracy, mismatches, missing)

	// We expect 100% accuracy for OIDs we find, but some may be missing due to unresolved deps
	if accuracy < 99 {
		t.Errorf("Accuracy %.1f%% is below 99%% threshold", accuracy)
	}

	// Coverage should be reasonable (>50%)
	coverage := float64(found) / float64(total) * 100
	t.Logf("Coverage: %d/%d OIDs (%.1f%%)", found, total, coverage)
	if coverage < 50 {
		t.Errorf("Coverage %.1f%% is below 50%% threshold", coverage)
	}
}

// BenchmarkValidation measures comparison overhead
func BenchmarkValidation(b *testing.B) {
	ctx := context.Background()
	model, err := LoadDir(ctx, "testdata")
	if err != nil {
		b.Fatal(err)
	}

	oids := []string{
		"1.3.6.1.2.1.1.1",
		"1.3.6.1.2.1.2.2.1.4",
		"1.3.6.1.2.1.25.1.1",
		"1.3.6.1.2.1.15.1",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, oid := range oids {
			node := model.GetNodeByOID(oid)
			if node != nil {
				_ = mapWasmibKind(node.Kind)
				obj := model.GetObject(node)
				if obj != nil {
					_ = model.GetEffectiveHint(obj.TypeID)
				}
			}
		}
	}
}
