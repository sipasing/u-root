// Copyright 2019 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	// "bytes"
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
	slDebug    = flag.Bool("d", false, "enable debug logs")
	logfile    = "sluinit_log"
	logBuilder strings.Builder
)

func checkDebugFlag() {
	/*
	 * check if uroot.uinitargs=-d is set in kernel cmdline.
	 * if set, everything is logged on stdout.
	 */
	flag.Parse()

	if flag.NArg() > 1 {
		log.Fatal("Incorrect number of arguments")
	}

	slaunch.Debug = log.Printf
	if *slDebug {
		slaunch.Debug("debug flag is set. logging everything to stdout")
	} else {
		log.Println("debug flag is not set, only errors logged to stderr")
		log.Println("debug flag is not set, logs written to file", logfile)
		log.Println("collecting measurements before kexec. please wait...")
		log.Println("This could take a couple of minutes")
		log.SetOutput(&logBuilder)
		log.Println() // empty line to start log builder
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

	slaunch.Debug("********Step 0: mount iscsi drives if any ********")
	err := scanIscsiDrives()
	if err != nil {
		log.Printf("NO ISCSI DRIVES found, err=[%v]", err)
	}

	defer unmountAndExit() // called only on error, on success we kexec
	slaunch.Debug("********Step 1: get TPM Handle  ********")
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

	slaunch.Debug("********Step 5: Parse eventlogs ********")
	if err := p.EventLog.Parse(); err != nil {
		log.Printf("EventLog.Parse() failed err=%v", err)
		return
	}

	if !*slDebug {
		slaunch.AddToPersistQueue("debug logs", []byte(logBuilder.String()), p.DebugFileLoc, logfile)
	}
	slaunch.Debug("********Step 6: Dump logs to disk********")
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
	if !*slDebug {
		log.SetOutput(os.Stdout)
		log.Print("exiting on error. log output set back to stdout")
		log.Println("len=", len(logBuilder.String()))
		log.Print(logBuilder.String())
	}
	os.Exit(1)
}

// scanIscsiDrives calls iscsinl to mount iscsi drives.
// format: netroot=iscsi:@X.Y.Z.W::3260::iqn.FOO.com.abc:hostname-boot
func scanIscsiDrives() error {

	log.Println("Scanning kernel cmd line for *netroot* flag")
	val, ok := cmdline.Flag("netroot")
	if !ok {
		return errors.New("netroot flag is not set")
	}

	// val = iscsi:@10.196.210.62::3260::iqn.1986-03.com.sun:ovs112-boot
	log.Println("netroot flag is set with val=", val)
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

	log.Println("Scanning kernel cmd line for *rd.iscsi.initiator* flag")
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
		log.Println("Mounted at dev ", devices[i])
	}
	return nil
}
