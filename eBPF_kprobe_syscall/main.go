package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf bpf_cgroup.c -- -I../headers -I/usr/include

func jailPIDs(cgroupPath string, pids []string) {
	procsFile := filepath.Join(cgroupPath, "cgroup.procs")
	f, err := os.OpenFile(procsFile, os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Printf("Warning: Could not open cgroup.procs: %v", err)
		return
	}
	defer f.Close()

	successCount := 0
	for _, pidStr := range pids {
		pidStr = strings.TrimSpace(pidStr)
		if pidStr == "" {
			continue
		}

		_, err := f.WriteString(pidStr + "\n")
		if err != nil {
			log.Printf("  [!] Failed to jail PID %s (It may have closed already)", pidStr)
		} else {
			successCount++
		}
	}
	log.Printf("Successfully jailed %d process(es)!", successCount)
}

func getPIDsByName(name string) ([]string, error) {
	cmd := exec.Command("pidof", name)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("could not find any running process named '%s'", name)
	}

	return strings.Split(strings.TrimSpace(out.String()), " "), nil
}

func main() {
	var targetPID int
	var targetName string
	var targetPort int

	flag.IntVar(&targetPID, "pid", 0, "Exact PID to jail")
	flag.StringVar(&targetName, "name", "", "Name of the process to jail")
	flag.IntVar(&targetPort, "port", 8080, "The ONLY port allowed")
	flag.Parse()

	if targetPID == 0 && targetName == "" {
		log.Fatal("You must provide either a -pid or a -name to jail!")
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	err := objs.PortMap.Update(uint32(0), uint16(targetPort), ebpf.UpdateAny)
	if err != nil {
		log.Fatalf("Failed to update PortMap: %v", err)
	}

	cgroupPath := "/sys/fs/cgroup/ebpf_jail"
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		log.Fatalf("Failed to create cgroup directory: %v", err)
	}
	defer os.Remove(cgroupPath)

	log.Printf("Created cgroup jail at %s", cgroupPath)

	egressLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: objs.EgressDrop,
	})
	if err != nil {
		log.Fatalf("Failed to attach egress program: %v", err)
	}
	defer egressLink.Close()

	ingressLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetIngress,
		Program: objs.IngressDrop,
	})
	if err != nil {
		log.Fatalf("Failed to attach ingress program: %v", err)
	}
	defer ingressLink.Close()

	log.Println("Firewall is active!")

	var pidsToJail []string
	if targetPID != 0 {
		log.Printf("Targeting exact PID: %d", targetPID)
		pidsToJail = append(pidsToJail, strconv.Itoa(targetPID))
	} else if targetName != "" {
		log.Printf("Hunting down all processes named: %s", targetName)
		foundPids, err := getPIDsByName(targetName)
		if err != nil {
			log.Fatalf("%v", err)
		}
		pidsToJail = foundPids
	}

	jailPIDs(cgroupPath, pidsToJail)

	log.Println("Press Ctrl+C to exit and lift the firewall.")

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	<-stopper

	log.Println("Detaching eBPF programs and shutting down...")
}