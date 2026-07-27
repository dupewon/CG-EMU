package types

import (
	"testing"
)

func TestConstants(t *testing.T) {
	tests := []struct {
		name string
		got  FileFormat
		want FileFormat
	}{
		{"PE", FormatPE, "pe"},
		{"ELF", FormatELF, "elf"},
		{"MachO", FormatMachO, "macho"},
		{"Raw", FormatRaw, "raw"},
		{"Unknown", FormatUnknown, "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("got %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestOffsetTypeConstants(t *testing.T) {
	tests := []struct {
		name string
		got  OffsetType
		want OffsetType
	}{
		{"Virtual", OffsetVirtual, "virtual"},
		{"Raw", OffsetRaw, "raw"},
		{"RVA", OffsetRVA, "rva"},
		{"File", OffsetFile, "file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("got %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestOffsetStruct(t *testing.T) {
	o := Offset{
		Name:    "test",
		Address: 0x1000,
		Size:    256,
		Offset:  0x200,
		Type:    OffsetVirtual,
		Section: ".text",
		File:    "test.bin",
		Format:  FormatPE,
	}
	if o.Name != "test" || o.Address != 0x1000 || o.Size != 256 {
		t.Errorf("Offset struct fields not set correctly")
	}
}

func TestSectionStruct(t *testing.T) {
	s := Section{
		Index:     1,
		Name:      ".text",
		Entropy:   7.5,
	}
	if s.Index != 1 || s.Name != ".text" || s.Entropy != 7.5 {
		t.Errorf("Section struct fields not set correctly")
	}
}

func TestBinaryInfoStruct(t *testing.T) {
	b := BinaryInfo{
		Path:   "test.exe",
		Size:   4096,
		Format: FormatPE,
		Arch:   "x86_64",
		OS:     "windows",
	}
	if b.Path != "test.exe" || b.Size != 4096 || b.Format != FormatPE {
		t.Errorf("BinaryInfo struct fields not set correctly")
	}
}

func TestPatternStruct(t *testing.T) {
	p := Pattern{
		Name:        "MZ_Header",
		Hex:         "4D5A",
		Description: "DOS MZ header",
	}
	if p.Name != "MZ_Header" || p.Hex != "4D5A" {
		t.Errorf("Pattern struct fields not set correctly")
	}
}

func TestMatchResultStruct(t *testing.T) {
	m := MatchResult{
		PatternName: "TEST",
		Offset:      0x100,
		Size:        4,
	}
	if m.PatternName != "TEST" || m.Offset != 0x100 {
		t.Errorf("MatchResult struct fields not set correctly")
	}
}

func TestScanResultStruct(t *testing.T) {
	s := ScanResult{
		Patterns: 5,
		Duration: "10ms",
	}
	if s.Patterns != 5 || s.Duration != "10ms" {
		t.Errorf("ScanResult struct fields not set correctly")
	}
}

func TestConfigStruct(t *testing.T) {
	c := Config{
		MinOffset: 0,
		MaxOffset: 1024,
		Alignment: 1,
	}
	if c.MinOffset != 0 || c.MaxOffset != 1024 || c.Alignment != 1 {
		t.Errorf("Config struct fields not set correctly")
	}
}
