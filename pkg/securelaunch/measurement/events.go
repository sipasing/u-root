// Copyright 2019 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package measurement provides different collectors to hash files, disks, dmi info and cpuid info.
package measurement

import (
    "encoding/binary"
    "bytes"

	"github.com/u-root/u-root/pkg/tss"
	"github.com/u-root/u-root/pkg/securelaunch/eventlog"
	slaunch "github.com/u-root/u-root/pkg/securelaunch"
)

var hashAlgo = tss.HashSHA256 // tss uses sha256

// marshalPcrEvent writes structure fields piecemeal to buffer.
func marshalPcrEvent(pcr uint32, h []byte, eventDesc []byte) ([]byte, error) {

	const baseTypeTXT = 0x400                       // TXT specification base event value for DRTM values
	const slaunchType = uint32(baseTypeTXT + 0x102) // Secure Launch event log entry type.
	count := uint32(1)
	eventDescLen := uint32(len(eventDesc))
	slaunch.Debug("marshalPcrEvent: pcr=[%v], slaunchType=[%v], count=[%v], hashAlgo=[%v], eventDesc=[%s], eventDescLen=[%v]",
		pcr, slaunchType, count, hashAlgo, eventDesc, eventDescLen)

	endianess := binary.LittleEndian
	var buf bytes.Buffer

	if err := binary.Write(&buf, endianess, pcr); err != nil {
		return nil, err
	}

	if err := binary.Write(&buf, endianess, slaunchType); err != nil {
		return nil, err
	}

	if err := binary.Write(&buf, endianess, count); err != nil {
		return nil, err
	}

	for i := uint32(0); i < count; i++ {
		if err := binary.Write(&buf, endianess, hashAlgo); err != nil {
			return nil, err
		}

		if err := binary.Write(&buf, endianess, h); err != nil {
			return nil, err
		}
	}

	if err := binary.Write(&buf, endianess, eventDescLen); err != nil {
		return nil, err
	}

	if err := binary.Write(&buf, endianess, eventDesc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// SendEventToSysfs marshals measurement events and writes them to sysfs.
func sendEventToSysfs(h []byte, pcr uint32, eventDesc string) error {

    slaunch.Debug(eventDesc)
	b, err := marshalPcrEvent(pcr, h, []byte(eventDesc))
	if err != nil {
		return err
	}

	if e := eventlog.Add(b); e != nil {
		return err
	}
    return nil
}
