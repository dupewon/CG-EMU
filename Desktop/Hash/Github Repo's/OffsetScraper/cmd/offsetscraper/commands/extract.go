package commands

import (
	"fmt"
	"strconv"

	"github.com/dupewon/OffsetScraper/pkg/extractor"
	"github.com/dupewon/OffsetScraper/pkg/output"
	"github.com/spf13/cobra"
)

var _ = fmt.Sprintf

var extractCmd = &cobra.Command{
	Use:   "extract [binary]",
	Short: "Extract bytes from binary at offset",
	Long:  `Extract raw bytes from a binary file at a specified offset.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		path := args[0]
		offsetStr, _ := cmd.Flags().GetString("offset")
		sizeStr, _ := cmd.Flags().GetString("size")
		section, _ := cmd.Flags().GetString("section")
		outFile, _ := cmd.Flags().GetString("out")

		e := extractor.New()

		var opt extractor.ExtractOption
		if section != "" {
			opt = extractor.ExtractOption{Section: section, OutputFile: outFile}
		} else {
			offset, _ := strconv.ParseUint(offsetStr, 0, 64)
			size, _ := strconv.ParseUint(sizeStr, 0, 64)
			opt = extractor.ExtractOption{FromOffset: offset, Size: size, OutputFile: outFile}
		}

		data, err := e.Extract(path, opt)
		if err != nil {
			return fmt.Errorf("extracting: %w", err)
		}

		w := output.New(output.Format(outputFormat))
		if outFile != "" {
			w.Write(map[string]interface{}{
				"path":   outFile,
				"size":   len(data),
				"offset": opt.FromOffset,
			})
		} else {
			w.Write(output.HexDump(data, opt.FromOffset))
		}
		return nil
	},
}

var dumpCmd = &cobra.Command{
	Use:   "dump [binary]",
	Short: "Hex dump a range of a binary",
	Long:  `Display a hex dump of a binary file section or range.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		path := args[0]
		section, _ := cmd.Flags().GetString("section")
		offsetStr, _ := cmd.Flags().GetString("offset")
		sizeStr, _ := cmd.Flags().GetString("size")

		e := extractor.New()

		var data []byte
		var baseOffset uint64
		var err error

		if section != "" {
			data, err = e.DumpSection(path, section)
			if err != nil {
				return err
			}
		} else {
			offset, _ := strconv.ParseUint(offsetStr, 0, 64)
			size, _ := strconv.ParseUint(sizeStr, 0, 64)
			opt := extractor.ExtractOption{FromOffset: offset, Size: size}
			data, err = e.Extract(path, opt)
			baseOffset = offset
			if err != nil {
				return err
			}
		}

		fmt.Print(output.HexDump(data, baseOffset))
		return nil
	},
}

func init() {
	extractCmd.Flags().String("offset", "0", "Offset to extract from")
	extractCmd.Flags().StringP("size", "s", "256", "Number of bytes to extract")
	extractCmd.Flags().StringP("section", "S", "", "Section to extract")
	extractCmd.Flags().StringP("out", "O", "", "Output file (omit for hex dump)")

	dumpCmd.Flags().StringP("section", "S", "", "Section to dump")
	dumpCmd.Flags().String("offset", "0", "Start offset")
	dumpCmd.Flags().StringP("size", "s", "512", "Number of bytes to dump")
}
