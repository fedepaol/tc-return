// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || amd64p32 || arm || arm64 || mips64le || mips64p32le || mipsle || ppc64le || riscv64
// +build 386 amd64 amd64p32 arm arm64 mips64le mips64p32le mipsle ppc64le riscv64

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadRedirect returns the embedded CollectionSpec for redirect.
func loadRedirect() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_RedirectBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load redirect: %w", err)
	}

	return spec, err
}

// loadRedirectObjects loads redirect and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*redirectObjects
//	*redirectPrograms
//	*redirectMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadRedirectObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadRedirect()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// redirectSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type redirectSpecs struct {
	redirectProgramSpecs
	redirectMapSpecs
}

// redirectSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type redirectProgramSpecs struct {
	Redirect *ebpf.ProgramSpec `ebpf:"redirect"`
}

// redirectMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type redirectMapSpecs struct {
	RedirectMapIpv4 *ebpf.MapSpec `ebpf:"redirect_map_ipv4"`
	RedirectMapIpv6 *ebpf.MapSpec `ebpf:"redirect_map_ipv6"`
}

// redirectObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadRedirectObjects or ebpf.CollectionSpec.LoadAndAssign.
type redirectObjects struct {
	redirectPrograms
	redirectMaps
}

func (o *redirectObjects) Close() error {
	return _RedirectClose(
		&o.redirectPrograms,
		&o.redirectMaps,
	)
}

// redirectMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadRedirectObjects or ebpf.CollectionSpec.LoadAndAssign.
type redirectMaps struct {
	RedirectMapIpv4 *ebpf.Map `ebpf:"redirect_map_ipv4"`
	RedirectMapIpv6 *ebpf.Map `ebpf:"redirect_map_ipv6"`
}

func (m *redirectMaps) Close() error {
	return _RedirectClose(
		m.RedirectMapIpv4,
		m.RedirectMapIpv6,
	)
}

// redirectPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadRedirectObjects or ebpf.CollectionSpec.LoadAndAssign.
type redirectPrograms struct {
	Redirect *ebpf.Program `ebpf:"redirect"`
}

func (p *redirectPrograms) Close() error {
	return _RedirectClose(
		p.Redirect,
	)
}

func _RedirectClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed redirect_bpfel.o
var _RedirectBytes []byte
