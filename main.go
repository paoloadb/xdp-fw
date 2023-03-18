package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"flag"
	"bufio"

	"github.com/dropbox/goebpf"
)

func main() {

	iFace := flag.String("iface", "", "Your interface name")
	fName := flag.String("fname", "blacklist.txt", "blacklist file name")
	flag.Parse()

	if *iFace == "" {
		failExit("Must specify interface name")
	}

	if *fName == "" {
		failExit("must provide filename")
	}
	// interfaceName := "wlx000f0032c4b9"
	// IP BlockList

	ipList := getIps(*fName)
    fmt.Println("list of blacklisted ip's:")
	for _, ips := range ipList {
		fmt.Println(ips)
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


func failExit(reason string) {
	fmt.Println(reason)
	os.Exit(1)
}

func getIps(fName string) []string {
	file, err := os.Open(fName)
	if err != nil {
		panic("file open error")
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// scanner.Split(bufio.ScanLines)
	var text []string 

	for scanner.Scan() {
		text = append(text, scanner.Text())
	}

return text
}