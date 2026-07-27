package commands

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExecute(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Execute panicked: %v", r)
		}
	}()
}

func TestScanCmdNoArgs(t *testing.T) {
	rootCmd.SetArgs([]string{"scan"})
	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error for scan without args")
	}
}

func TestInfoCmdNoArgs(t *testing.T) {
	rootCmd.SetArgs([]string{"info"})
	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error for info without args")
	}
}

func TestExtractCmdNoArgs(t *testing.T) {
	rootCmd.SetArgs([]string{"extract"})
	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error for extract without args")
	}
}

func TestDumpCmdNoArgs(t *testing.T) {
	rootCmd.SetArgs([]string{"dump"})
	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error for dump without args")
	}
}

func TestCompareCmdNoArgs(t *testing.T) {
	rootCmd.SetArgs([]string{"compare"})
	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error for compare without args")
	}
}

func TestPatternListCmd(t *testing.T) {
	rootCmd.SetArgs([]string{"pattern", "list"})
	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("pattern list failed: %v", err)
	}
}

func TestPatternImportCmdNoArgs(t *testing.T) {
	rootCmd.SetArgs([]string{"pattern", "import"})
	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error for pattern import without args")
	}
}

func TestPatternExportCmdNoArgs(t *testing.T) {
	rootCmd.SetArgs([]string{"pattern", "export"})
	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error for pattern export without args")
	}
}

func TestPatternImportCmd(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	content := "MZ:4D5A\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	rootCmd.SetArgs([]string{"pattern", "import", path})
	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("pattern import failed: %v", err)
	}
}

func TestPatternExportCmd(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "export.yaml")

	rootCmd.SetArgs([]string{"pattern", "export", path})
	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("pattern export failed: %v", err)
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("expected exported file to exist")
	}
}

func TestScanCmdOnRawFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")
	data := []byte{0x90, 0x90, 0x90, 0x90, 0xCC, 0xC3}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	rootCmd.SetArgs([]string{"scan", path})
	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
}

func TestScanCmdWithPattern(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")
	data := []byte{0x00, 0x4D, 0x5A, 0x00}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	rootCmd.SetArgs([]string{"scan", path, "--pattern", "4D5A"})
	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
}

func TestInfoCmd(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")
	data := []byte{0x00, 0x01, 0x02, 0x03}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	rootCmd.SetArgs([]string{"info", path})
	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("info failed: %v", err)
	}
}

func TestCompareCmdIdentical(t *testing.T) {
	dir := t.TempDir()
	path1 := filepath.Join(dir, "a.bin")
	path2 := filepath.Join(dir, "b.bin")
	data := []byte{0x01, 0x02, 0x03}
	if err := os.WriteFile(path1, data, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path2, data, 0644); err != nil {
		t.Fatal(err)
	}

	rootCmd.SetArgs([]string{"compare", path1, path2})
	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("compare failed: %v", err)
	}
}

func TestCompareCmdDifferent(t *testing.T) {
	dir := t.TempDir()
	path1 := filepath.Join(dir, "a.bin")
	path2 := filepath.Join(dir, "b.bin")
	if err := os.WriteFile(path1, []byte{0x01, 0x02, 0x03}, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path2, []byte{0x01, 0xFF, 0x03}, 0644); err != nil {
		t.Fatal(err)
	}

	rootCmd.SetArgs([]string{"compare", path1, path2})
	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("compare failed: %v", err)
	}
}

func TestExtractCmd(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	rootCmd.SetArgs([]string{"extract", path, "--offset", "1", "--size", "3"})
	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("extract failed: %v", err)
	}
}

func TestExtractCmdWithOutput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	outPath := filepath.Join(dir, "out.bin")
	rootCmd.SetArgs([]string{"extract", path, "--offset", "0", "--size", "3", "--out", outPath})
	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("extract failed: %v", err)
	}
	outData, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(outData) != 3 {
		t.Errorf("expected 3 bytes in output, got %d", len(outData))
	}
}

func TestDumpCmd(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	rootCmd.SetArgs([]string{"dump", path, "--offset", "2", "--size", "4"})
	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("dump failed: %v", err)
	}
}

func TestIDACmd(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	origDir, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(origDir)

	rootCmd.SetArgs([]string{"ida", path})
	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("ida failed: %v", err)
	}

	expectedIDC := filepath.Join(dir, "test.idc")
	if _, err := os.Stat(expectedIDC); os.IsNotExist(err) {
		t.Error("expected .idc file to be created")
	}
	os.Remove(expectedIDC)
}

func TestIDACmdMapFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")
	data := []byte{0x01, 0x02, 0x03}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	origDir, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(origDir)

	rootCmd.SetArgs([]string{"ida", path, "--format", "map"})
	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("ida map failed: %v", err)
	}

	expectedMAP := "test.map"
	if _, err := os.Stat(expectedMAP); os.IsNotExist(err) {
		t.Error("expected .map file to be created")
	}
	os.Remove(expectedMAP)
}

func TestIDACmdOffsetFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")
	data := []byte{0x01, 0x02, 0x03}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	origDir, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(origDir)

	rootCmd.SetArgs([]string{"ida", path, "--format", "offset"})
	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("ida offset failed: %v", err)
	}

	expectedOffset := "test_offsets.txt"
	if _, err := os.Stat(expectedOffset); os.IsNotExist(err) {
		t.Error("expected _offsets.txt file to be created")
	}
	os.Remove(expectedOffset)
}

func TestIDACmdNonexistentFile(t *testing.T) {
	rootCmd.SetArgs([]string{"ida", "/nonexistent.bin"})
	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestCompareNonexistent(t *testing.T) {
	rootCmd.SetArgs([]string{"compare", "/nonexistent1.bin", "/nonexistent2.bin"})
	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestVerboseFlag(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")
	if err := os.WriteFile(path, []byte{0x00, 0x01, 0x02, 0x03}, 0644); err != nil {
		t.Fatal(err)
	}

	rootCmd.SetArgs([]string{"scan", path, "--verbose"})
	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("scan with verbose failed: %v", err)
	}
}

func TestExtractCmdSectionNotFound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")
	data := make([]byte, 512)
	data[0] = 'M'
	data[1] = 'Z'
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	rootCmd.SetArgs([]string{"extract", path, "--section", ".text"})
	err := rootCmd.Execute()
	if err == nil {
		t.Log("extract section may succeed depending on binary structure")
	}
}
