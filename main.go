package main

import (
	"fmt"
	"log"
	"net"

	"github.com/PraserX/ipconv"
	"github.com/vishvananda/netlink"

	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go redirect ./ebpf/redirect.c -- -I./ebpf

func main() {
	objs := &redirectObjects{}
	if err := loadRedirectObjects(objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	attachFilter("eth0", objs)
	ip := net.ParseIP("192.168.1.5")
	nextHopIP := net.ParseIP("10.111.221.21")
	enableRedirect(ip, nextHopIP, "eth1", objs)
}

func attachFilter(attachTo string, objs *redirectObjects) error {
	redirect := objs.redirectPrograms.Redirect
	devID, err := net.InterfaceByName(attachTo)
	if err != nil {
		return fmt.Errorf("could not get interface ID: %w", err)
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: devID.Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}

	err = netlink.QdiscReplace(qdisc)
	if err != nil {
		return fmt.Errorf("could not get replace qdisc: %w", err)
	}

	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: devID.Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           redirect.FD(),
		Name:         redirect.String(),
		DirectAction: true,
	}

	if err := netlink.FilterReplace(filter); err != nil {
		return fmt.Errorf("failed to replace tc filter: %w", err)
	}
	return nil
}

func enableRedirect(src, nextHop net.IP, interfaceName string, objs *redirectObjects) error {
	eth1ID, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return fmt.Errorf("could not get interface ID: %w", err)
	}

	key, err := ipconv.IPv4ToInt(src)
	if err != nil {
		return fmt.Errorf("convert ip failed %w", err)
	}

	next, err := ipconv.IPv4ToInt(nextHop)
	if err != nil {
		return fmt.Errorf("convert ip failed %w", err)
	}
	record := struct {
		interfaceID uint32
		nextHopIP   uint32
	}{
		uint32(eth1ID.Index),
		next,
	}
	err = objs.RedirectMapIpv4.Put(key, record)
	if err != nil {
		return fmt.Errorf("add to map failed %w", err)
	}
	return nil
}
