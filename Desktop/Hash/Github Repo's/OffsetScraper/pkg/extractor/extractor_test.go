package extractor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNew(t *testing.T) {
	e := New()
	if e == nil {
		t.Fatal("expected non-nil Extractor")
	}
}

func TestExtractByOffset(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")
	data := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	e := New()
	extracted, err := e.Extract(path, ExtractOption{FromOffset: 2, Size: 4})
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}
	if len(extracted) != 4 {
		t.Errorf("expected 4 bytes, got %d", len(extracted))
	}
	if extracted[0] != 0x02 || extracted[3] != 0x05 {
		t.Errorf("unexpected data: %v", extracted)
	}
}

func TestExtractNonexistentFile(t *testing.T) {
	e := New()
	_, err := e.Extract("/nonexistent/file.bin", ExtractOption{FromOffset: 0, Size: 1})
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestExtractOffsetExceedsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")
	if err := os.WriteFile(path, []byte{0x01, 0x02}, 0644); err != nil {
		t.Fatal(err)
	}

	e := New()
	_, err := e.Extract(path, ExtractOption{FromOffset: 10, Size: 1})
	if err == nil {
		t.Error("expected error for offset exceeding file size")
	}
}

func TestExtractSizeClamped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")
	data := []byte{0x01, 0x02, 0x03}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	e := New()
	extracted, err := e.Extract(path, ExtractOption{FromOffset: 1, Size: 100})
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}
	if len(extracted) != 2 {
		t.Errorf("expected 2 bytes (clamped), got %d", len(extracted))
	}
}

func TestExtractWithOutputFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")
	data := []byte{0x01, 0x02, 0x03, 0x04}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	outPath := filepath.Join(dir, "output.bin")
	e := New()
	extracted, err := e.Extract(path, ExtractOption{FromOffset: 1, Size: 2, OutputFile: outPath})
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}
	if len(extracted) != 2 {
		t.Errorf("expected 2 bytes, got %d", len(extracted))
	}
	outData, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(outData) != 2 || outData[0] != 0x02 {
		t.Errorf("unexpected output file content: %v", outData)
	}
}

func TestExtractByAddress(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")
	peData := makePE()
	if err := os.WriteFile(path, peData, 0644); err != nil {
		t.Fatal(err)
	}

	e := New()
	extracted, err := e.ExtractByAddress(path, 0x1000, 4)
	if err != nil {
		t.Fatalf("ExtractByAddress failed: %v", err)
	}
	if len(extracted) == 0 {
		t.Error("expected non-empty extraction")
	}
}

func TestExtractByAddressNotFound(t *testing.T) {
	e := New()
	_, err := e.ExtractByAddress("/nonexistent.bin", 0xDEAD, 4)
	if err == nil {
		t.Error("expected error for address not in any section")
	}
}

func TestDumpSectionNonexistent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")
	if err := os.WriteFile(path, []byte{0x01}, 0644); err != nil {
		t.Fatal(err)
	}

	e := New()
	_, err := e.DumpSection(path, ".nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent section")
	}
}

func TestDumpRangeHex(t *testing.T) {
	e := New()
	data := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}
	result := e.DumpRangeHex(data, 0, 16)
	if !strings.Contains(result, "00000000") {
		t.Errorf("expected address in dump, got '%s'", result)
	}
	if !strings.Contains(result, "00 01 02 03") {
		t.Errorf("expected hex content, got '%s'", result)
	}
}

func TestDumpRangeHexEmpty(t *testing.T) {
	e := New()
	data := []byte{0x01, 0x02}
	result := e.DumpRangeHex(data, 5, 10)
	if result != "" {
		t.Errorf("expected empty result for out-of-range, got '%s'", result)
	}
}

func TestDumpRangeHexEndClamped(t *testing.T) {
	e := New()
	data := []byte{0x01, 0x02, 0x03}
	result := e.DumpRangeHex(data, 1, 100)
	if !strings.Contains(result, "02 03") {
		t.Errorf("expected clamped hex dump, got '%s'", result)
	}
}

func TestTrimNull(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{"no null", []byte(".text"), ".text"},
		{"with null", []byte(".text\x00\x00\x00"), ".text"},
		{"all null", []byte{0x00, 0x00}, ""},
		{"empty", []byte{}, ""},
		{"null at start", []byte{0x00, 'a'}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := trimNull(tt.input)
			if got != tt.want {
				t.Errorf("trimNull(%v) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func makePE() []byte {
	data := make([]byte, 1024)
	data[0] = 'M'
	data[1] = 'Z'

	peOffset := uint32(0x40)
	data[0x3C] = byte(peOffset)
	data[0x3D] = byte(peOffset >> 8)
	data[0x3E] = byte(peOffset >> 16)
	data[0x3F] = byte(peOffset >> 24)

	data[peOffset] = 'P'
	data[peOffset+1] = 'E'
	data[peOffset+2] = 0x00
	data[peOffset+3] = 0x00

	data[peOffset+4] = 0x4C
	data[peOffset+5] = 0x01

	data[peOffset+0x14] = 0xE0
	data[peOffset+0x15] = 0x00

	data[peOffset+0x28] = 0x00
	data[peOffset+0x29] = 0x10
	data[peOffset+0x2A] = 0x00
	data[peOffset+0x2B] = 0x00

	numSections := uint16(1)
	data[peOffset+6] = byte(numSections)
	data[peOffset+7] = byte(numSections >> 8)

	optHeaderSize := uint16(0xE0)
	data[peOffset+0x14] = byte(optHeaderSize)
	data[peOffset+0x15] = byte(optHeaderSize >> 8)

	sectionOffset := peOffset + 24 + uint32(optHeaderSize)
	name := []byte(".text\x00\x00\x00")
	copy(data[sectionOffset:], name)

	va := uint32(0x1000)
	data[sectionOffset+12] = byte(va)
	data[sectionOffset+13] = byte(va >> 8)
	data[sectionOffset+14] = byte(va >> 16)
	data[sectionOffset+15] = byte(va >> 24)

	vs := uint32(0x200)
	data[sectionOffset+8] = byte(vs)
	data[sectionOffset+9] = byte(vs >> 8)
	data[sectionOffset+10] = byte(vs >> 16)
	data[sectionOffset+11] = byte(vs >> 24)

	rawOffset := uint32(0x200)
	data[sectionOffset+20] = byte(rawOffset)
	data[sectionOffset+21] = byte(rawOffset >> 8)
	data[sectionOffset+22] = byte(rawOffset >> 16)
	data[sectionOffset+23] = byte(rawOffset >> 24)

	rawSize := uint32(0x100)
	data[sectionOffset+16] = byte(rawSize)
	data[sectionOffset+17] = byte(rawSize >> 8)
	data[sectionOffset+18] = byte(rawSize >> 16)
	data[sectionOffset+19] = byte(rawSize >> 24)

	data[0x200] = 0xDE
	data[0x201] = 0xAD
	data[0x202] = 0xBE
	data[0x203] = 0xEF

	return data
}
