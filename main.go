package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/PraserX/ipconv"
	tc "github.com/florianl/go-tc"
	"golang.org/x/sys/unix"
)

func TC_H_MAKE(maj, min uint32) uint32 {
	return ((maj & 0xFFFF0000) | (min & 0x0000FFFF))
}

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go redirect ./ebpf/redirect.c -- -I./ebpf

func uint32Ptr(v uint32) *uint32 {
	return &v
}

func stringPtr(v string) *string {
	return &v
}

func main() {

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	objs := &redirectObjects{}
	if err := loadRedirectObjects(objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	redirect := objs.redirectPrograms.Redirect

	// Setup tc socket for communication with the kernel
	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not open rtnetlink socket: %v\n", err)
		return
	}
	defer func() {
		if err := tcnl.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "could not close rtnetlink socket: %v\n", err)
		}
	}()

	devID, err := net.InterfaceByName("eth0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not get interface ID: %v\n", err)
		return
	}

	qdisc := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(devID.Index),
			Handle:  TC_H_MAKE(tc.HandleIngress, 0x0000),
			Parent:  tc.HandleIngress,
		},
		Attribute: tc.Attribute{
			Kind: "clsact",
		},
	}
	if err := tcnl.Qdisc().Add(&qdisc); err != nil {
		fmt.Fprintf(os.Stderr, "could not assign clsact to %s: %v\n", "eth0", err)
		return
	}
	// when deleting the qdisc, the applied filter will also be gone
	defer tcnl.Qdisc().Delete(&qdisc)

	filter := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(devID.Index),
			Handle:  0,
			Parent:  TC_H_MAKE(tc.HandleIngress, tc.HandleMinEgress),
			Info:    0x10300,
		},
		Attribute: tc.Attribute{
			Kind: "bpf",
			BPF: &tc.Bpf{
				FD:    uint32Ptr(uint32(redirect.FD())),
				Name:  stringPtr(redirect.String()),
				Flags: uint32Ptr(0x1),
			},
		},
	}
	if err := tcnl.Filter().Add(&filter); err != nil {
		fmt.Fprintf(os.Stderr, "could not assign eBPF: %v\n", err)
		return
	}

	eth1ID, err := net.InterfaceByName("eth1")
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not get interface ID: %v\n", err)
		return
	}

	ip := net.ParseIP("192.168.1.5")
	key, err := ipconv.IPv4ToInt(ip)
	fmt.Println("FEDE key", key, ip)
	if err != nil {
		fmt.Println("convert ip failed", err)
		return
	}

	err = objs.RedirectMapIpv4.Put(key, uint32(eth1ID.Index))
	if err != nil {
		fmt.Println("add to map failed", err)
		return
	}
	<-ctx.Done()

	if err := tcnl.Filter().Delete(&filter); err != nil {
		fmt.Fprintf(os.Stderr, "could not delete eBPF filter: %v\n", err)
		return
	}
	if err := tcnl.Qdisc().Delete(&qdisc); err != nil {
		fmt.Fprintf(os.Stderr, "could not delete eBPF qdisc: %v\n", err)
		return
	}

}

// Made it work following https://github.com/florianl/tc-skeleton/discussions/2
