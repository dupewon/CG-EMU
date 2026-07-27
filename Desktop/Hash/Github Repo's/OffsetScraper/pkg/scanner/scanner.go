package scanner

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
	"time"

	"github.com/dupewon/OffsetScraper/pkg/types"
)

type Scanner struct {
	config types.Config
}

func New(cfg types.Config) *Scanner {
	return &Scanner{config: cfg}
}

func (s *Scanner) Scan(path string) (*types.ScanResult, error) {
	start := time.Now()
	result := &types.ScanResult{}

	_, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("accessing file: %w", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	binInfo, err := s.analyzeBinary(path, data)
	if err != nil {
		return nil, fmt.Errorf("analyzing binary: %w", err)
	}
	result.Binary = *binInfo

	patterns := s.config.Patterns
	if len(patterns) == 0 {
		patterns = DefaultPatterns()
	}

	for _, p := range patterns {
		matches := s.findPattern(data, p, binInfo)
		result.Matches = append(result.Matches, matches...)
	}

	result.Patterns = len(patterns)
	result.Duration = time.Since(start).Round(time.Millisecond).String()

	return result, nil
}

func (s *Scanner) analyzeBinary(path string, data []byte) (*types.BinaryInfo, error) {
	info := &types.BinaryInfo{
		Path: path,
		Size: int64(len(data)),
	}

	if len(data) < 4 {
		info.Format = types.FormatRaw
		return info, nil
	}

	if data[0] == 0x4d && data[1] == 0x5a {
		info.Format = types.FormatPE
		f, err := pe.Open(path)
		if err != nil {
			return info, fmt.Errorf("opening PE: %w", err)
		}
		defer f.Close()

		switch f.Machine {
		case pe.IMAGE_FILE_MACHINE_I386:
			info.Arch = "i386"
		case pe.IMAGE_FILE_MACHINE_AMD64:
			info.Arch = "x86_64"
		case pe.IMAGE_FILE_MACHINE_ARM64:
			info.Arch = "arm64"
		case pe.IMAGE_FILE_MACHINE_THUMB:
			info.Arch = "arm"
		}
		info.OS = "windows"

		if f.Symbols != nil {
			for _, sym := range f.Symbols {
				info.Symbols = append(info.Symbols, sym.Name)
			}
		}

		for _, s := range f.Symbols {
			if s.Value != 0 {
				info.Exports = append(info.Exports, s.Name)
			} else {
				info.Imports = append(info.Imports, s.Name)
			}
		}

		for i, sec := range f.Sections {
			info.Sections = append(info.Sections, types.Section{
				Index:          i,
				Name:           sec.Name,
				VirtualAddress: uint64(sec.VirtualAddress),
				VirtualSize:    uint64(sec.VirtualSize),
				RawOffset:      uint64(sec.Offset),
				RawSize:        uint64(sec.Size),
				Flags:          fmt.Sprintf("0x%x", sec.Characteristics),
			})
		}
		return info, nil
	}

	if data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F' {
		info.Format = types.FormatELF
		f, err := elf.Open(path)
		if err != nil {
			return info, fmt.Errorf("opening ELF: %w", err)
		}
		defer f.Close()

		switch f.Machine {
		case elf.EM_386:
			info.Arch = "i386"
		case elf.EM_X86_64:
			info.Arch = "x86_64"
		case elf.EM_AARCH64:
			info.Arch = "arm64"
		case elf.EM_ARM:
			info.Arch = "arm"
		}

		info.EntryPoint = f.Entry
		info.OS = "linux"

		symbols, _ := f.DynamicSymbols()
		for _, sym := range symbols {
			info.Symbols = append(info.Symbols, sym.Name)
		}

		for i, sec := range f.Sections {
			flags := ""
			if sec.Flags&elf.SHF_EXECINSTR != 0 {
				flags += "X"
			}
			if sec.Flags&elf.SHF_WRITE != 0 {
				flags += "W"
			}
			if sec.Flags&elf.SHF_ALLOC != 0 {
				flags += "A"
			}
			info.Sections = append(info.Sections, types.Section{
				Index:          i,
				Name:           sec.Name,
				VirtualAddress: sec.Addr,
				VirtualSize:    sec.Size,
				RawOffset:      sec.Offset,
				RawSize:        sec.FileSize,
				Flags:          flags,
			})
		}
		return info, nil
	}

	if isMachO(data) {
		info.Format = types.FormatMachO
		f, err := macho.Open(path)
		if err != nil {
			return info, fmt.Errorf("opening Mach-O: %w", err)
		}
		defer f.Close()

		switch f.Cpu {
		case macho.Cpu386:
			info.Arch = "i386"
		case macho.CpuAmd64:
			info.Arch = "x86_64"
		case macho.CpuArm64:
			info.Arch = "arm64"
		}
		info.OS = "macos"

		for i, sec := range f.Sections {
			info.Sections = append(info.Sections, types.Section{
				Index:          i,
				Name:           sec.Name,
				VirtualAddress: sec.Addr,
				VirtualSize:    sec.Size,
		RawOffset:      uint64(sec.Offset),
		RawSize:        sec.Size,
			})
		}
		return info, nil
	}

	info.Format = types.FormatRaw
	return info, nil
}

func (s *Scanner) findPattern(data []byte, p types.Pattern, bin *types.BinaryInfo) []types.MatchResult {
	pattern := hexToBytes(p.Hex)
	if len(pattern) == 0 {
		return nil
	}

	mask := p.Mask
	sections := bin.Sections

	var results []types.MatchResult

	if len(sections) > 0 && p.SectionHint != "" {
		for _, sec := range sections {
			start := sec.RawOffset
			end := start + sec.RawSize
			if end > uint64(len(data)) {
				end = uint64(len(data))
			}
			matches := s.searchRange(data[start:end], p, pattern, mask, start)
			for i := range matches {
				matches[i].Section = sec.Name
			}
			results = append(results, matches...)
		}
		return results
	}

	startOffset := s.config.MinOffset
	endOffset := s.config.MaxOffset
	if endOffset == 0 || endOffset > uint64(len(data)) {
		endOffset = uint64(len(data))
	}

	return s.searchRange(data[startOffset:endOffset], p, pattern, mask, startOffset)
}

func (s *Scanner) searchRange(data []byte, p types.Pattern, pattern []byte, mask string, baseOffset uint64) []types.MatchResult {
	var results []types.MatchResult

	if mask != "" {
		maskBytes := hexToBytes(mask)
		if len(maskBytes) != len(pattern) {
			maskBytes = make([]byte, len(pattern))
			for i := range maskBytes {
				maskBytes[i] = 0xFF
			}
		}
		results = s.searchMasked(data, p, pattern, maskBytes, baseOffset)
		return results
	}

	align := s.config.Alignment
	if align == 0 {
		align = 1
	}

	for i := 0; i <= len(data)-len(pattern); i += align {
		match := true
		for j := 0; j < len(pattern); j++ {
			if data[i+j] != pattern[j] {
				match = false
				break
			}
		}
		if match {
			offset := baseOffset + uint64(i)
			addr := offset
			ctxEnd := i + 16
			if ctxEnd > len(data) {
				ctxEnd = len(data)
			}
			results = append(results, types.MatchResult{
				PatternName: p.Name,
				Offset:      offset,
				Address:     addr,
				Size:        len(pattern),
				Context:     fmt.Sprintf("%x", data[i:ctxEnd]),
				Hex:         fmt.Sprintf("%x", pattern),
			})
		}
	}

	return results
}

func (s *Scanner) searchMasked(data []byte, p types.Pattern, pattern, mask []byte, baseOffset uint64) []types.MatchResult {
	var results []types.MatchResult
	align := s.config.Alignment
	if align == 0 {
		align = 1
	}

	for i := 0; i <= len(data)-len(pattern); i += align {
		match := true
		for j := 0; j < len(pattern); j++ {
			if mask[j] != 0 && data[i+j] != pattern[j] {
				match = false
				break
			}
		}
		if match {
			results = append(results, types.MatchResult{
				PatternName: p.Name,
				Offset:      baseOffset + uint64(i),
				Hex:         fmt.Sprintf("%x", pattern),
			})
		}
	}

	return results
}

func hexToBytes(s string) []byte {
	if len(s) == 0 || len(s)%2 != 0 {
		return nil
	}
	bytes := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		high := nibble(s[i])
		low := nibble(s[i+1])
		if high == 0xFF || low == 0xFF {
			return nil
		}
		bytes[i/2] = (high << 4) | low
	}
	return bytes
}

func nibble(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	case c == '?' || c == '.' || c == '*':
		return 0xFF
	}
	return 0xFF
}

func isMachO(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	if data[0] == 0xfe && data[1] == 0xed && data[2] == 0xfa && data[3] == 0xce {
		return true
	}
	if data[0] == 0xfe && data[1] == 0xed && data[2] == 0xfa && data[3] == 0xcf {
		return true
	}
	if data[0] == 0xce && data[1] == 0xfa && data[2] == 0xed && data[3] == 0xfe {
		return true
	}
	if data[0] == 0xcf && data[1] == 0xfa && data[2] == 0xed && data[3] == 0xfe {
		return true
	}
	if data[0] == 0xca && data[1] == 0xfe && data[2] == 0xba && data[3] == 0xbe {
		return true
	}
	return false
}

func DefaultPatterns() []types.Pattern {
	return []types.Pattern{
		{Name: "MZ_Header", Hex: "4D5A", Description: "DOS MZ header"},
		{Name: "PE_Signature", Hex: "50450000", Description: "PE\\0\\0 signature", Offset: 0x3C},
		{Name: "ELF_Magic", Hex: "7F454C46", Description: "ELF magic bytes"},
		{Name: "JMP_Relative", Hex: "E9", Description: "near JMP (E9 xx xx xx xx)"},
		{Name: "CALL_Relative", Hex: "E8", Description: "near CALL (E8 xx xx xx xx)"},
		{Name: "NOP_Sled", Hex: "90909090", Description: "NOP sled (4 bytes)"},
		{Name: "INT3", Hex: "CC", Description: "INT3 / debug breakpoint"},
		{Name: "RET", Hex: "C3", Description: "near return"},
		{Name: "RETN", Hex: "C2", Description: "near return with pop"},
		{Name: "PUSHAD", Hex: "60", Description: "push all registers"},
		{Name: "POPAD", Hex: "61", Description: "pop all registers"},
		{Name: "MOV_ESP_EBP", Hex: "8BEC", Description: "mov esp, ebp"},
		{Name: "MOV_EBP_ESP", Hex: "89E5", Description: "mov ebp, esp"},
	}
}

var _ = binary.Size
