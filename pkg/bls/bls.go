// Copyright 2017-2019 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package bls provides utilities for parsing BLS boot entries.
// See spec at https://systemd.io/BOOT_LOADER_SPECIFICATION
package bls

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/u-root/u-root/pkg/boot"
	"github.com/u-root/u-root/pkg/mount"
	"golang.org/x/sys/unix"
)

const (
	blsEntriesDir = "loader/entries"
	efiEntriesDir = "EFI/Linux"
)

// FindAllEntries scans the given filesystem for valid BLS and EFI entries,
// and returns all valid entries found.
func FindAllEntries(device, fsRoot, fsType string) (blsEntries []boot.LinuxImage, efiEntries []boot.LinuxImage, err error) {
	if err = os.MkdirAll(fsRoot, 0755); err != nil {
		err = fmt.Errorf("Could not create mount directory %q: %v", fsRoot, err)
		return
	}

	mp, err := mount.Mount(device, fsRoot, fsType, "norecovery", unix.MS_RDONLY)
	if err != nil {
		err = fmt.Errorf("Could not mount %q as %q: %v", device, fsRoot, err)
		return
	}

	blsEntries, berr := ScanBLSEntries(mp.Path)
	if berr != nil {
		log.Printf("error scanning BLS entries: %v", berr)
	}
	efiEntries, ferr := ScanEFIEntries(mp.Path)
	if ferr != nil {
		log.Printf("error scanning EFI entries: %v", ferr)
	}

	err = mp.Unmount(0)
	return
}

// ScanBLSEntries scans the filesystem root for valid BLS entries.
// This function skips over invalid or unreadable entries in an effort
// to return everything that is bootable.
func ScanBLSEntries(fsRoot string) ([]boot.LinuxImage, error) {
	entriesDir := filepath.Join(fsRoot, blsEntriesDir)

	files, err := filepath.Glob(path.Join(entriesDir, "*.conf"))
	if err != nil {
		return nil, err
	}

	result := []boot.LinuxImage{}
	for _, f := range files {
		entry, err := parseBLSEntry(f, entriesDir)
		if err != nil {
			fmt.Println("Skipping over invalid BLS entry", f, " err: ", err)
			continue
		}
		result = append(result, *entry)
	}
	return result, nil
}

// ScanEFIEntries scans the filesystem root for valid EFI entries.
// This function skips over invalid or unreadable entries in an effort
// to return everything that is bootable.
func ScanEFIEntries(fsRoot string) ([]boot.LinuxImage, error) {
	entriesDir := filepath.Join(fsRoot, efiEntriesDir)

	files, err := filepath.Glob(path.Join(entriesDir, "*.efi"))
	if err != nil {
		return nil, err
	}

	result := []boot.LinuxImage{}
	for _, f := range files {
		entry, err := parseEFIEntry(f)
		if err != nil {
			fmt.Println("Skipping over invalid EFI entry", f, " err: ", err)
			continue
		}
		result = append(result, *entry)
	}
	return result, nil
}

// ParseBLSEntry takes a Type #1 BLS entry and the directory of entries, and
// returns a LinuxImage.
// An error is returned if the syntax is wrong or required keys are missing.
func parseBLSEntry(entry, entriesDir string) (*boot.LinuxImage, error) {
	baseDir := filepath.Dir(entriesDir)

	f, err := os.Open(entry)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)

	bc := &boot.LinuxImage{}
	options := []string{}

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		sline := strings.Fields(line)
		if len(sline) != 2 {
			continue
		}
		key, val := sline[0], sline[1]

		switch key {
		case "linux":
			f, err := os.Open(filepath.Join(baseDir, val))
			if err != nil {
				return nil, err
			}
			bc.Kernel = f
		case "initrd":
			f, err := os.Open(filepath.Join(baseDir, val))
			if err != nil {
				return nil, err
			}
			bc.Initrd = f
		case "options":
			options = append(options, val)
		}
	}

	// validate - spec says kernel and initrd are required
	if bc.Kernel == nil || bc.Initrd == nil {
		return nil, fmt.Errorf("malformed BLS config, kernel or initrd missing")
	}
	bc.Cmdline = strings.Join(options, " ")
	return bc, nil
}

// ParseEFIEntry takes a Type #2 EFI Unified Kernel Image and returns a LinuxImage.
// An error is returned if the syntax is wrong or required keys are missing.
func parseEFIEntry(entry string) (*boot.LinuxImage, error) {
	// TODO: fix this
	return nil, fmt.Errorf("EFI entries are not yet supported")
}
