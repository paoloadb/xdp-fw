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
	fName := flag.String("fname", "", "file containing ip list")
	fMode := flag.String("fmode", "", "blacklist or whitelist")
	// interfaceName := "wlx000f0032c4b9"
	flag.Parse()

	if *iFace == "" {
		failExit("Must specify interface name")
	}
	if *fName == "" {
		failExit("must provide filename")
	}

	// check mode
	var elfName string
	if *fMode == "blacklist" {
		fmt.Println("Blacklist mode...")
		elfName = "bpf/xdp-black.elf"
	}  
	if *fMode == "whitelist" {
		fmt.Println("Whitelist mode...")
		elfName = "bpf/xdp-white.elf"
	}

	// reads ip's from ip-list.txt
	ipList := getIps(*fName)
    fmt.Println("list of ip's in file:")
	for _, ips := range ipList {
		fmt.Println(ips)
	}

	// Code To Load XDP Into App
	bpf := goebpf.NewDefaultEbpfSystem()


	err := bpf.LoadElf(elfName)
	if err != nil {
		log.Fatalf("LoadELF() failed: %s", err)
	}
	blacklist := bpf.GetMapByName("list")
	if blacklist == nil {
		log.Fatalf("eBPF map 'list' not found\n")
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
	log.Println("Program Loaded successfuly!")
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