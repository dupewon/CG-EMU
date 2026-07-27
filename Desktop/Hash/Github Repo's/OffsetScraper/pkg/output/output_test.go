package output

import (
	"bytes"
	"strings"
	"testing"
)

type testStringer struct {
	value string
}

func (t testStringer) String() string {
	return t.value
}

func TestNew(t *testing.T) {
	w := New(FormatText)
	if w.Format != FormatText {
		t.Errorf("expected FormatText, got %s", w.Format)
	}
	if w.Writer == nil {
		t.Error("expected non-nil Writer")
	}
}

func TestWriteText(t *testing.T) {
	var buf bytes.Buffer
	w := &Writer{Format: FormatText, Writer: &buf}
	w.Write("hello world")
	if !strings.Contains(buf.String(), "hello world") {
		t.Errorf("expected 'hello world', got '%s'", buf.String())
	}
}

func TestWriteJSON(t *testing.T) {
	var buf bytes.Buffer
	w := &Writer{Format: FormatJSON, Writer: &buf}
	w.Write(map[string]string{"key": "value"})
	output := buf.String()
	if !strings.Contains(output, `"key"`) || !strings.Contains(output, `"value"`) {
		t.Errorf("expected JSON output, got '%s'", output)
	}
}

func TestWriteYAML(t *testing.T) {
	var buf bytes.Buffer
	w := &Writer{Format: FormatYAML, Writer: &buf}
	w.Write(map[string]string{"key": "value"})
	output := buf.String()
	if !strings.Contains(output, "key:") || !strings.Contains(output, "value") {
		t.Errorf("expected YAML output, got '%s'", output)
	}
}

func TestWriteStringer(t *testing.T) {
	var buf bytes.Buffer
	w := &Writer{Format: FormatText, Writer: &buf}
	w.Write(testStringer{value: "stringer-value"})
	if !strings.Contains(buf.String(), "stringer-value") {
		t.Errorf("expected 'stringer-value', got '%s'", buf.String())
	}
}

func TestWriteStructAsYAML(t *testing.T) {
	var buf bytes.Buffer
	w := &Writer{Format: FormatText, Writer: &buf}
	w.Write(struct{ Name string }{Name: "test"})
	output := buf.String()
	if !strings.Contains(output, "name:") || !strings.Contains(output, "test") {
		t.Errorf("expected YAML-like output, got '%s'", output)
	}
}

func TestTable(t *testing.T) {
	headers := []string{"Name", "Value"}
	rows := [][]string{{"foo", "1"}, {"bar", "2"}}
	result := Table(headers, rows)
	if !strings.Contains(result, "foo") || !strings.Contains(result, "bar") {
		t.Errorf("expected table content, got '%s'", result)
	}
	if !strings.Contains(result, "------------") {
		t.Errorf("expected separator, got '%s'", result)
	}
}

func TestHexDump(t *testing.T) {
	data := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}
	result := HexDump(data, 0)
	if !strings.Contains(result, "00000000") {
		t.Errorf("expected address in hex dump, got '%s'", result)
	}
	if !strings.Contains(result, "00 01 02 03") {
		t.Errorf("expected hex bytes in dump, got '%s'", result)
	}
	if !strings.Contains(result, "|") {
		t.Errorf("expected pipe separators in hex dump, got '%s'", result)
	}
}

func TestHexDumpPartialLastLine(t *testing.T) {
	data := []byte{0x41, 0x42, 0x43}
	result := HexDump(data, 0x1000)
	if !strings.Contains(result, "00001000") {
		t.Errorf("expected base address in hex dump, got '%s'", result)
	}
	if !strings.Contains(result, "41 42 43") {
		t.Errorf("expected hex bytes, got '%s'", result)
	}
	if !strings.Contains(result, "ABC") {
		t.Errorf("expected ASCII representation, got '%s'", result)
	}
}

func TestHexDumpNonPrintable(t *testing.T) {
	data := []byte{0x00, 0x01, 0x7F, 0x41}
	result := HexDump(data, 0)
	if !strings.Contains(result, "...A") {
		t.Errorf("expected dots for non-printable chars, got '%s'", result)
	}
}

func TestWriteFormats(t *testing.T) {
	tests := []struct {
		name   string
		format Format
	}{
		{"text", FormatText},
		{"json", FormatJSON},
		{"yaml", FormatYAML},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := &Writer{Format: tt.format, Writer: &buf}
			w.Write("test")
			if buf.Len() == 0 {
				t.Error("expected non-empty output")
			}
		})
	}
}
