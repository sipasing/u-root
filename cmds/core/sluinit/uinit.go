// Copyright 2019 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/u-root/iscsinl"
	"github.com/u-root/u-root/pkg/cmdline"
	slaunch "github.com/u-root/u-root/pkg/securelaunch"
	"github.com/u-root/u-root/pkg/securelaunch/policy"
	"github.com/u-root/u-root/pkg/securelaunch/tpm"
)

var (
	slDebug = flag.Bool("d", false, "enable debug logs")
	noTPM   = flag.Bool("t", false, "disable TPM")
)

func checkDebugFlag() {
	/*
	 * check if uroot.uinitargs=-d is set in kernel cmdline.
	 * if set, slaunch.Debug is set to log.Printf.
	 */
	flag.Parse()

	if flag.NArg() > 1 {
		log.Fatal("Incorrect number of arguments")
	}

	if *slDebug {
		slaunch.Debug = log.Printf
		slaunch.Debug("debug flag is set. Logging Enabled.")
	}

	if *noTPM {
		slaunch.Debug = log.Printf
		slaunch.Debug("TPM flag enables debug flag by default.Logging Enabled.")
		slaunch.Debug("TPM is disabled. No measurements will be taken.")
		slaunch.NoTPM = true
	}
}

/*
 * main parses platform policy file, and based on the inputs,
 * performs measurements and then launches a target kernel.
 *
 * steps followed by sluinit:
 * 1. if debug flag is set, enable logging.
 * 2. gets the TPM handle
 * 3. Gets secure launch policy file entered by user.
 * 4. calls collectors to collect measurements(hashes) a.k.a evidence.
 */
func main() {
	checkDebugFlag()

	defer unmountAndExit() // called only on error, on success we kexec
	slaunch.Debug("********Step 1: init completed. starting main ********")
	if err := tpm.New(); err != nil {
		log.Printf("tpm.New() failed. err=%v", err)
		return
	}
	defer tpm.Close()

	slaunch.Debug("********Step 2: locate and parse SL Policy ********")
	p, err := policy.Get()
	if err != nil {
		log.Printf("failed to get policy err=%v", err)
		return
	}
	slaunch.Debug("policy file successfully parsed")

	slaunch.Debug("********Step 3: Collecting Evidence ********")
	for _, c := range p.Collectors {
		slaunch.Debug("Input Collector: %v", c)
		if e := c.Collect(); e != nil {
			log.Printf("Collector %v failed, err = %v", c, e)
		}
	}
	slaunch.Debug("Collectors completed")

	slaunch.Debug("********Step 4: Measuring target kernel, initrd ********")
	if err := p.Launcher.MeasureKernel(); err != nil {
		log.Printf("Launcher.MeasureKernel failed err=%v", err)
		return
	}

	slaunch.Debug("********Step 5: Parse eventlogs *********")
	if err := p.EventLog.Parse(); err != nil {
		log.Printf("EventLog.Parse() failed err=%v", err)
		return
	}

	slaunch.Debug("*****Step 6: Dump logs to disk *******")
	if err := slaunch.ClearPersistQueue(); err != nil {
		log.Printf("ClearPersistQueue failed err=%v", err)
		return
	}

	slaunch.Debug("********Step *: Unmount all ********")
	slaunch.UnmountAll()

	slaunch.Debug("********Step 7: Launcher called to Boot ********")
	if err := p.Launcher.Boot(); err != nil {
		log.Printf("Boot failed. err=%s", err)
		return
	}
}

// unmountAndExit is called on error and unmounts all devices.
// sluinit ends here.
func unmountAndExit() {
	slaunch.UnmountAll()
	time.Sleep(5 * time.Second) // let queued up debug statements get printed
	os.Exit(1)
}

// scanIscsiDrives calls iscsinl to mount iscsi drives.
// format: netroot=iscsi:@X.Y.Z.W::3260::iqn.FOO.com.abc:hostname-boot
func scanIscsiDrives() error {

	slaunch.Debug("Scanning kernel cmd line for *netroot* flag")
	val, ok := cmdline.Flag("netroot")
	if !ok {
		return errors.New("netroot flag is not set")
	}

	// IP v4 address is any address of format 0-255 . 0-255 . 0-255 . 0-255
	//r := regexp.MustCompile(`(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)){3}`)
	//fmt.Println(r.MatchString("10.123.234.182"))

	// val = iscsi:@10.196.210.62::3260::iqn.1986-03.com.sun:ovs112-boot
	slaunch.Debug("netroot flag is set with val=%s", val)
	s := strings.Split(val, "::")
	if len(s) != 3 {
		return fmt.Errorf("%v: incorrect format ::,  Usage: netroot=iscsi:@10.X.Y.Z::1224::iqn.foo:hostname-bar, [Expecting len(%s) = 3] ", val, s)
	}

	// s[0] = iscsi:@10.196.210.62 or iscsi:@10.196.210.62,2
	// s[1] = 3260
	// s[2] = iqn.1986-03.com.sun:ovs112-boot
	port := s[1]
	volume := s[2]

	// split s[0] into tmp[1] and tmp[2]
	tmp := strings.Split(s[0], ":@")
	if len(tmp) > 3 || len(tmp) < 2 {
		return fmt.Errorf("%v: incorrect format :@, Usage: netroot=iscsi:@10.X.Y.Z::1224::iqn.foo:hostname-bar, [ Expecting 2 <= len(%s) <= 3", val, tmp)
	}

	if tmp[0] != "iscsi" {
		return fmt.Errorf("%v: incorrect format iscsi:, Usage: netroot=iscsi:@10.X.Y.Z::1224::iqn.foo:hostname-bar, [ %s != 'iscsi'] ", val, tmp[0])
	}

	ip := tmp[1] + ":" + port

	slaunch.Debug("Scanning kernel cmd line for *rd.iscsi.initiator* flag")
	initiatorName, ok := cmdline.Flag("rd.iscsi.initiator")
	if !ok {
		return errors.New("rd.iscsi.initiator flag is not set")
	}

	devices, err := iscsinl.MountIscsi(
		iscsinl.WithInitiator(initiatorName),
		iscsinl.WithTarget(ip, volume),
		iscsinl.WithCmdsMax(128),
		iscsinl.WithQueueDepth(16),
		iscsinl.WithScheduler("noop"),
	)
	if err != nil {
		return err
	}

	for i := range devices {
		slaunch.Debug("Mounted at dev %v", devices[i])
	}
	return nil
}

func init() {
	err := scanIscsiDrives()
	if err != nil {
		log.Printf("NO ISCSI DRIVES found, err=[%v]", err)
	}
}
