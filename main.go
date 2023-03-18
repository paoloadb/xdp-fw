package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"flag"

	"github.com/dropbox/goebpf"
)

func main() {

	iFace := flag.String("iface", "", "Your interface name")
	flag.Parse()

	if *iFace == "" {
		fmt.Println("Must specify interface name")
		os.Exit(1)
	}
	// interfaceName := "wlx000f0032c4b9"
	// IP BlockList
	// TODO: write a function to read ip's from a file
	ipList := []string{
		"192.168.254.110",
	}

	// Load XDP Into App
	bpf := goebpf.NewDefaultEbpfSystem()
	err := bpf.LoadElf("bpf/xdp.elf")
	if err != nil {
		log.Fatalf("LoadELF() failed: %s", err)
	}
	blacklist := bpf.GetMapByName("blacklist")
	if blacklist == nil {
		log.Fatalf("eBPF map 'blacklist' not found\n")
	}
	xdp := bpf.GetProgramByName("firewall")
	if xdp == nil {
		log.Fatalln("Program 'firewall' not found in Program")
	}
	err = xdp.Load()
	if err != nil {
		fmt.Printf("xdp.Attach(): %v", err)
	}
	err = xdp.Attach(*iFace)
	if err != nil {
		log.Fatalf("Error attaching to Interface: %s", err)
	}

	BlockIPAddress(ipList, blacklist)

	defer xdp.Detach()
	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)
	log.Println("XDP Program Loaded successfuly into the Kernel.")
	log.Println("Press CTRL+C to stop.")
	<-ctrlC

}

// The Function That adds the IPs to the blacklist map
func BlockIPAddress(ipAddreses []string, blacklist goebpf.Map) error {
	for index, ip := range ipAddreses {
		err := blacklist.Insert(goebpf.CreateLPMtrieKey(ip), index)
		if err != nil {
			return err
		}
	}
	return nil
}
