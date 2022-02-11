/* Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf -cflags "-D__TARGET_ARCH_x86" bpf_redir   bpf/bpf_redir.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf -cflags "-D__TARGET_ARCH_x86" bpf_sockops bpf/bpf_sockops.c

import (
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	v2 "github.com/containers/common/pkg/cgroupv2"
	"golang.org/x/sys/unix"
	"os"
	"os/signal"
	"path/filepath"
)

const (
	MapsPinpath = "/sys/fs/bpf/tcpip-bypass"
)

type BypassProgram struct {
	sockops_Obj    bpf_sockopsObjects
	redir_Obj   bpf_redirObjects
	SockopsCgroup  link.Link
}

func setLimit() error {
	var err error = nil

	err = unix.Setrlimit(unix.RLIMIT_MEMLOCK,
		&unix.Rlimit{
			Cur: unix.RLIM_INFINITY,
			Max: unix.RLIM_INFINITY,
		})
	if err != nil {
		fmt.Println("failed to set rlimit:", err)
	}

	return err
}

func getCgroupPath() (string, error) {
	var err error = nil
	cgroupPath := "/sys/fs/cgroup"

	enabled, err := v2.Enabled()
	if !enabled {
		cgroupPath = filepath.Join(cgroupPath, "unified")
	}
	return cgroupPath, err
}

func loadProgram(prog BypassProgram) (BypassProgram, error) {
	var err error
	var options ebpf.CollectionOptions

	err = os.Mkdir(MapsPinpath, os.ModePerm)
	if err != nil{
		fmt.Println(err)
	}

	options.Maps.PinPath = MapsPinpath

	if err = loadBpf_redirObjects(&prog.redir_Obj, &options); err != nil {
		fmt.Println("Error load objects:", err)
	}

	if err = link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  prog.redir_Obj.bpf_redirMaps.MapRedir.FD(),
		Program: prog.redir_Obj.bpf_redirPrograms.BpfRedirProxy,
		Attach:  ebpf.AttachSkMsgVerdict,
	}); err != nil {
		fmt.Printf("Error attaching to sockmap: %s\n", err)
	}

	if err = loadBpf_sockopsObjects(&prog.sockops_Obj, &options); err != nil {
		fmt.Println("Error load objects:", err)
	}

	if cgroupPath, err := getCgroupPath(); err == nil {
		prog.SockopsCgroup, err = link.AttachCgroup(link.CgroupOptions{
			Path:    cgroupPath,
			Attach:  ebpf.AttachCGroupSockOps,
			Program: prog.sockops_Obj.bpf_sockopsPrograms.BpfSockmap,
		})
		if err != nil {
			fmt.Printf("Error attaching sockops to cgroup: %s", err)
		}

	}

	return prog, err
}

func closeProgram(prog BypassProgram) {
	var err error

	if prog.SockopsCgroup != nil {
		fmt.Printf("Closing sockops cgroup...\n")
		prog.SockopsCgroup.Close()
	}

	if prog.redir_Obj.bpf_redirPrograms.BpfRedirProxy != nil {
		err = link.RawDetachProgram(link.RawDetachProgramOptions{
			Target:  prog.redir_Obj.bpf_redirMaps.MapRedir.FD(),
			Program: prog.redir_Obj.bpf_redirPrograms.BpfRedirProxy,
			Attach:  ebpf.AttachSkMsgVerdict,
		})
		if err != nil {
			fmt.Printf("Error detaching '%s'\n", err)
		}

		fmt.Printf("Closing redirect prog...\n")
	}

	if prog.sockops_Obj.bpf_sockopsMaps.MapActiveEstab != nil {
		prog.sockops_Obj.bpf_sockopsMaps.MapActiveEstab.Unpin()
		prog.sockops_Obj.bpf_sockopsMaps.MapActiveEstab.Close()
	}

	if prog.sockops_Obj.bpf_sockopsMaps.MapProxy != nil {
		prog.sockops_Obj.bpf_sockopsMaps.MapProxy.Unpin()
		prog.sockops_Obj.bpf_sockopsMaps.MapProxy.Close()
	}

	if prog.sockops_Obj.bpf_sockopsMaps.MapRedir != nil {
		prog.sockops_Obj.bpf_sockopsMaps.MapRedir.Unpin()
		prog.sockops_Obj.bpf_sockopsMaps.MapRedir.Close()
	}

	if prog.sockops_Obj.bpf_sockopsMaps.DebugMap != nil {
		prog.sockops_Obj.bpf_sockopsMaps.DebugMap.Unpin()
		prog.sockops_Obj.bpf_sockopsMaps.DebugMap.Close()
	}

}

func main() {
	var prog BypassProgram
	var err error

	if err := setLimit(); err != nil {
		fmt.Println("Setting limit failed:", err)
		return
	}

	prog,err = loadProgram(prog)
	if err != nil {
		fmt.Println("Loading program failed:", err)
		return
	}
	defer closeProgram(prog)

	fmt.Println("Run...")
	defer fmt.Println("Exiting...")

	c := make(chan os.Signal, 1)
	signal.Notify(c)
	<-c
}
