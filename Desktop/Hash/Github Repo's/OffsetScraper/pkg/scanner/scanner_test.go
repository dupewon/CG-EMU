package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dupewon/OffsetScraper/pkg/types"
)

func TestNew(t *testing.T) {
	s := New(types.Config{})
	if s == nil {
		t.Fatal("expected non-nil Scanner")
	}
}

func TestHexToBytes(t *testing.T) {
	tests := []struct {
		input string
		want  []byte
	}{
		{"4D5A", []byte{0x4D, 0x5A}},
		{"", nil},
		{"50450000", []byte{0x50, 0x45, 0x00, 0x00}},
		{"A", nil},
		{"ZZ", nil},
	}
	for _, tt := range tests {
		got := hexToBytes(tt.input)
		if len(got) != len(tt.want) {
			t.Errorf("hexToBytes(%q) returned len %d, want %d", tt.input, len(got), len(tt.want))
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("hexToBytes(%q)[%d] = %02x, want %02x", tt.input, i, got[i], tt.want[i])
			}
		}
	}
}

func TestHexToBytesWildcard(t *testing.T) {
	bytes := hexToBytes("4D?A")
	if bytes != nil {
		t.Errorf("expected nil for wildcard hex, got %v", bytes)
	}
}

func TestNibble(t *testing.T) {
	tests := []struct {
		c    byte
		want byte
	}{
		{'0', 0x0},
		{'9', 0x9},
		{'a', 0xA},
		{'f', 0xF},
		{'A', 0xA},
		{'F', 0xF},
		{'?', 0xFF},
		{'.', 0xFF},
		{'*', 0xFF},
		{'z', 0xFF},
	}
	for _, tt := range tests {
		got := nibble(tt.c)
		if got != tt.want {
			t.Errorf("nibble(%q) = %02x, want %02x", tt.c, got, tt.want)
		}
	}
}

func TestIsMachO(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"empty", []byte{}, false},
		{"short", []byte{0xFE}, false},
		{"FEEDFACE", []byte{0xFE, 0xED, 0xFA, 0xCE}, true},
		{"FEEDFACF", []byte{0xFE, 0xED, 0xFA, 0xCF}, true},
		{"CEFAEDFE", []byte{0xCE, 0xFA, 0xED, 0xFE}, true},
		{"CFFAEDFE", []byte{0xCF, 0xFA, 0xED, 0xFE}, true},
		{"CAFEBABE", []byte{0xCA, 0xFE, 0xBA, 0xBE}, true},
		{"not macho", []byte{0x00, 0x00, 0x00, 0x00}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isMachO(tt.data)
			if got != tt.want {
				t.Errorf("isMachO(%x) = %v, want %v", tt.data, got, tt.want)
			}
		})
	}
}

func TestDefaultPatterns(t *testing.T) {
	patterns := DefaultPatterns()
	if len(patterns) == 0 {
		t.Fatal("expected non-empty default patterns")
	}
	for _, p := range patterns {
		if p.Name == "" {
			t.Error("pattern with empty name found")
		}
		if p.Hex == "" {
			t.Errorf("pattern %q has empty hex", p.Name)
		}
	}
}

func TestScanNonexistentFile(t *testing.T) {
	s := New(types.Config{})
	_, err := s.Scan("/nonexistent/file.bin")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestScanEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.bin")
	if err := os.WriteFile(path, []byte{}, 0644); err != nil {
		t.Fatal(err)
	}
	s := New(types.Config{})
	result, err := s.Scan(path)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if result.Binary.Size != 0 {
		t.Errorf("expected size 0, got %d", result.Binary.Size)
	}
	if result.Binary.Format != types.FormatRaw {
		t.Errorf("expected FormatRaw, got %s", result.Binary.Format)
	}
}

func TestScanRawData(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")
	data := []byte{0xAA, 0x90, 0x90, 0x90, 0x90, 0xCC, 0xC3}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	s := New(types.Config{
		Patterns: []types.Pattern{
			{Name: "NOP", Hex: "90909090"},
			{Name: "INT3", Hex: "CC"},
			{Name: "RET", Hex: "C3"},
		},
	})
	result, err := s.Scan(path)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if result.Binary.Format != types.FormatRaw {
		t.Errorf("expected FormatRaw, got %s", result.Binary.Format)
	}
	if len(result.Matches) == 0 {
		t.Fatal("expected matches")
	}
}

func TestScanWithAlignment(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")
	data := []byte{0x00, 0xAA, 0xBB, 0x00, 0xAA, 0xBB, 0x00, 0x00}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	s := New(types.Config{
		Patterns:  []types.Pattern{{Name: "AABB", Hex: "AABB"}},
		Alignment: 4,
	})
	result, err := s.Scan(path)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	for _, m := range result.Matches {
		if m.Offset%4 != 0 {
			t.Errorf("with alignment 4, expected offset %% 4 == 0, got offset %d", m.Offset)
		}
	}
}

func TestScanWithMinMaxOffset(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")
	data := make([]byte, 100)
	data[10] = 0xAA
	data[11] = 0xBB
	data[50] = 0xAA
	data[51] = 0xBB
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	s := New(types.Config{
		Patterns:  []types.Pattern{{Name: "AABB", Hex: "AABB"}},
		MinOffset: 0,
		MaxOffset: 30,
	})
	result, err := s.Scan(path)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if len(result.Matches) != 1 {
		t.Errorf("expected 1 match in range [0,30), got %d", len(result.Matches))
	}
}

func TestScanWithMask(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")
	data := []byte{0x00, 0xFF, 0x00, 0xFF}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	s := New(types.Config{
		Patterns: []types.Pattern{
			{Name: "Masked", Hex: "00FF00FF", Mask: "FF00FF00"},
		},
	})
	result, err := s.Scan(path)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if len(result.Matches) != 1 {
		t.Errorf("expected 1 match (masked pattern should match with bits skipped), got %d", len(result.Matches))
	}
}

func TestScanWithMaskExact(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")
	data := []byte{0x00, 0xFF, 0x00, 0xFF}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	s := New(types.Config{
		Patterns: []types.Pattern{
			{Name: "Exact", Hex: "00FF00FF", Mask: "FFFFFFFF"},
		},
	})
	result, err := s.Scan(path)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if len(result.Matches) != 1 {
		t.Errorf("expected 1 exact match, got %d", len(result.Matches))
	}
}

func TestScanWithMaskLengthMismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")
	data := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	s := New(types.Config{
		Patterns: []types.Pattern{
			{Name: "ShortMask", Hex: "AABBCCDD", Mask: "FF"},
		},
	})
	result, err := s.Scan(path)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if len(result.Matches) != 1 {
		t.Errorf("expected 1 match with short mask (mask gets padded), got %d", len(result.Matches))
	}
}

func TestAnalyzeBinaryRaw(t *testing.T) {
	s := New(types.Config{})
	dir := t.TempDir()
	path := filepath.Join(dir, "raw.bin")
	data := []byte{0x00, 0x01, 0x02, 0x03}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	info, err := s.analyzeBinary(path, data)
	if err != nil {
		t.Fatalf("analyzeBinary failed: %v", err)
	}
	if info.Format != types.FormatRaw {
		t.Errorf("expected FormatRaw, got %s", info.Format)
	}
}

func TestFindPatternEmpty(t *testing.T) {
	s := New(types.Config{})
	matches := s.findPattern([]byte{0xAA, 0xBB}, types.Pattern{Name: "empty", Hex: ""}, &types.BinaryInfo{})
	if len(matches) != 0 {
		t.Error("expected 0 matches for empty pattern")
	}
}

func TestSearchRangeWithOffset(t *testing.T) {
	s := New(types.Config{})
	data := []byte{0x00, 0xAA, 0xBB, 0x00}
	matches := s.searchRange(data, types.Pattern{Name: "AABB", Hex: "AABB"}, []byte{0xAA, 0xBB}, "", 0)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Offset != 1 {
		t.Errorf("expected offset 1, got %d", matches[0].Offset)
	}
}

func TestSearchRangeBaseOffset(t *testing.T) {
	s := New(types.Config{})
	data := []byte{0xAA, 0xBB}
	matches := s.searchRange(data, types.Pattern{Name: "AABB", Hex: "AABB"}, []byte{0xAA, 0xBB}, "", 0x1000)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Offset != 0x1000 {
		t.Errorf("expected offset 0x1000, got 0x%x", matches[0].Offset)
	}
}
