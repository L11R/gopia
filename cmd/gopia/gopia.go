package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"go-pia-manual-connections/pia"
)

func main() {
	var (
		username string
		password string
	)
	flag.StringVar(&username, "username", "", "Your PIA username")
	flag.StringVar(&password, "password", "", "Your PIA password")
	flag.Parse()

	if username == "" || password == "" {
		fmt.Println("Please pass username and password first!")
		os.Exit(0)
	}

	client, err := pia.NewClient()
	if err != nil {
		panic(err)
	}

	servers, err := client.Servers(true, 50 * time.Millisecond)
	if err != nil {
		panic(err)
	}

	for _, r := range servers.Regions {
		fmt.Print(r.ID, ":", r.Latency.String(), "\n\n")

		config, err := client.CreateWireGuardConfig(username, password, r.Servers)
		if err != nil {
			fmt.Println(err)
		}

		fmt.Print(config, "\n\n")
	}
}