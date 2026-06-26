package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf xdp_prog_kernel.c -- -I/usr/include

func main() {
	if len(os.Args) < 3 {
		fmt.Print("usage: loader <interface_name> <port_to_block>\n")
		os.Exit(-1)
	}

	ifaceName := os.Args[1]
	iface, err := net.InterfaceByName(ifaceName)

	if err != nil {
		log.Fatalf("Encountered the following error while setting up the interface %s: %s", ifaceName, err)
	}

	portToBlock := os.Args[2]
	port, err := strconv.ParseUint(portToBlock, 10, 32)

	if err != nil {
		log.Fatalf("invalid port number : %s. error is: %v", portToBlock, err)
	}
	

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects %s", err)
	}

	defer objs.Close()

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpParserFunction,
		Interface: iface.Index,
	})

	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}

	defer l.Close()

	log.Printf("Attached XDP program to interface : %q", iface.Name)
	log.Printf("Press Ctrl-C to exit and remove the program")

	var key uint32 = 0
	typecastedPort := uint32(port)
	objs.ConfigMap.Update(&key, &typecastedPort, ebpf.UpdateAny)

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	<-stopper

	log.Println("Detaching XDP block and cleaning up...")
}
