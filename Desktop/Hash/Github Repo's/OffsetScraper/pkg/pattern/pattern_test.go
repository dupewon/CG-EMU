package pattern

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dupewon/OffsetScraper/pkg/types"
)

func TestNew(t *testing.T) {
	m := New()
	if m == nil {
		t.Fatal("expected non-nil Manager")
	}
	if m.Count() != 0 {
		t.Errorf("expected 0 patterns, got %d", m.Count())
	}
}

func TestAddAndList(t *testing.T) {
	m := New()
	m.Add(types.Pattern{Name: "test", Hex: "4D5A"})
	if m.Count() != 1 {
		t.Errorf("expected 1 pattern, got %d", m.Count())
	}
	patterns := m.List()
	if len(patterns) != 1 || patterns[0].Name != "test" {
		t.Errorf("unexpected patterns: %+v", patterns)
	}
}

func TestAddBuiltin(t *testing.T) {
	m := New()
	m.AddBuiltin()
	if m.Count() == 0 {
		t.Error("expected builtin patterns to be added")
	}
}

func TestGet(t *testing.T) {
	m := New()
	m.Add(types.Pattern{Name: "MZ", Hex: "4D5A"})
	p := m.Get("MZ")
	if p == nil {
		t.Fatal("expected to find pattern 'MZ'")
	}
	if p.Hex != "4D5A" {
		t.Errorf("expected hex '4D5A', got '%s'", p.Hex)
	}
	p = m.Get("nonexistent")
	if p != nil {
		t.Errorf("expected nil for nonexistent pattern")
	}
}

func TestRemove(t *testing.T) {
	m := New()
	m.Add(types.Pattern{Name: "a", Hex: "AA"})
	m.Add(types.Pattern{Name: "b", Hex: "BB"})
	m.Add(types.Pattern{Name: "c", Hex: "CC"})
	if !m.Remove("b") {
		t.Error("expected Remove to return true")
	}
	if m.Count() != 2 {
		t.Errorf("expected 2 patterns, got %d", m.Count())
	}
	if m.Get("b") != nil {
		t.Error("expected 'b' to be removed")
	}
	if m.Remove("nonexistent") {
		t.Error("expected Remove to return false for nonexistent")
	}
}

func TestClear(t *testing.T) {
	m := New()
	m.Add(types.Pattern{Name: "a", Hex: "AA"})
	m.Clear()
	if m.Count() != 0 {
		t.Errorf("expected 0 patterns after Clear, got %d", m.Count())
	}
}

func TestFromBytes(t *testing.T) {
	m := New()
	p := m.FromBytes("test", []byte{0x4D, 0x5A})
	if p.Name != "test" || p.Hex != "4D5A" {
		t.Errorf("unexpected pattern: %+v", p)
	}
}

func TestLoadJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "patterns.json")
	content := `[{"name":"MZ","hex":"4D5A","description":"MZ header"}]`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	m := New()
	if err := m.Load(path); err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if m.Count() != 1 {
		t.Errorf("expected 1 pattern, got %d", m.Count())
	}
}

func TestLoadYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "patterns.yaml")
	content := "- name: MZ\n  hex: 4D5A\n  description: MZ header\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	m := New()
	if err := m.Load(path); err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if m.Count() != 1 {
		t.Errorf("expected 1 pattern, got %d", m.Count())
	}
}

func TestLoadTextPatterns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "patterns.txt")
	content := "MZ_Header:4D5A\nPE_Sig:50450000\n# comment\n; also comment\n// another comment\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	m := New()
	if err := m.Load(path); err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if m.Count() != 2 {
		t.Errorf("expected 2 patterns, got %d", m.Count())
	}
}

func TestLoadIDAPatterns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "script.idc")
	content := `MakeName(0x401000, "main");
MakeName(0x401200, "sub_401200");
static main() {}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	m := New()
	if err := m.Load(path); err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if m.Count() != 2 {
		t.Errorf("expected 2 patterns, got %d", m.Count())
	}
}

func TestLoadCodeSigPatterns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pattern.sig")
	content := `; comment
MZ_Header 4D 5A
PE_Sig 50 45 00 00
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	m := New()
	if err := m.Load(path); err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if m.Count() != 2 {
		t.Errorf("expected 2 patterns, got %d", m.Count())
	}
}

func TestLoadUnknownExt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "patterns.unknown")
	content := "MZ_Header:4D5A\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	m := New()
	if err := m.Load(path); err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if m.Count() != 1 {
		t.Errorf("expected 1 pattern, got %d", m.Count())
	}
}

func TestSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "exported.yaml")
	m := New()
	m.Add(types.Pattern{Name: "MZ", Hex: "4D5A"})
	if err := m.Save(path); err != nil {
		t.Fatalf("Save failed: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty saved file")
	}
}

func TestLoadNonexistentFile(t *testing.T) {
	m := New()
	err := m.Load("/nonexistent/file.json")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestBuiltinPatterns(t *testing.T) {
	m := New()
	m.AddBuiltin()
	patterns := m.List()
	if len(patterns) == 0 {
		t.Fatal("expected builtin patterns")
	}
	names := make(map[string]bool)
	for _, p := range patterns {
		if names[p.Name] {
			t.Errorf("duplicate pattern name: %s", p.Name)
		}
		names[p.Name] = true
		if p.Hex == "" {
			t.Errorf("pattern %s has empty hex", p.Name)
		}
	}
}
