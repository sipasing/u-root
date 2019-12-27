package bls

import (
	"path/filepath"
	"testing"
)

var fsRoot = "testdata"

var blsEntries = []struct {
	entry string
	err   string
}{
	{
		entry: "entry-1.conf",
	},
	{
		entry: "entry-2.conf",
		err:   "malformed BLS config, kernel or initrd missing",
	},
}

func TestParseBLSEntries(t *testing.T) {
	dir := filepath.Join(fsRoot, "loader/entries")

	for _, tt := range blsEntries {
		t.Run(tt.entry, func(t *testing.T) {
			image, err := parseBLSEntry(filepath.Join(dir, tt.entry), dir)
			if err != nil {
				if tt.err == "" {
					t.Fatalf("Expected no error, got error %v", err)
				}
				if err.Error() != tt.err {
					t.Fatalf("Expected error %s, got error %v", tt.err, err)
				}
				return
			}
			if tt.err != "" {
				t.Fatalf("Expected error %s, got no error", tt.err)
			}
			t.Logf("Got image: %s", image.String())
		})
	}
}

func TestScanBLSEntries(t *testing.T) {
	entries, err := ScanBLSEntries(fsRoot)
	if err != nil {
		t.Errorf("Error scanning BLS entries: %v", err)
	}

	// TODO: have a better way of checking contents
	if len(entries) < 1 {
		t.Errorf("Expected at least BLS entry, found none")
	}
}
