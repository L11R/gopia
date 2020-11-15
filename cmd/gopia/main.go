package main

import (
	"errors"
	"flag"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/L11R/gopia/pia"

	"github.com/manifoldco/promptui"
)

func main() {
	var (
		username string
		password string
		err      error
	)
	flag.StringVar(&username, "u", "", "Your PIA username")
	flag.StringVar(&password, "p", "", "Your PIA password")
	flag.Parse()

	if username == "" || password == "" {
		usernamePrompt := promptui.Prompt{
			Label: "Username",
			Validate: func(input string) error {
				if !strings.HasPrefix(input, "p") || len(input) < 2 {
					return errors.New("invalid username, it should starts from 'p'")
				}

				_, err := strconv.Atoi(string([]rune(input)[1:]))
				if err != nil {
					return errors.New("invalid username")
				}

				return nil
			},
		}

		username, err = usernamePrompt.Run()
		if err != nil {
			fmt.Printf("Prompt failed: %v\n", err)
			return
		}

		passwordPrompt := promptui.Prompt{
			Label: "Password",
			Mask:  '*',
		}

		password, err = passwordPrompt.Run()
		if err != nil {
			fmt.Printf("Prompt failed: %v\n", err)
			return
		}
	}

	client, err := pia.NewClient()
	if err != nil {
		fmt.Printf("Error while initializing PIA client: %v\n", err)
		return
	}

	withLatencyPrompt := promptui.Prompt{
		Label:     "Sort servers by latency",
		IsConfirm: true,
	}
	_, err = withLatencyPrompt.Run()
	withLatency := err == nil

	var latency time.Duration
	if withLatency {
		latencyPrompt := promptui.Prompt{
			Label:     "Maximum latency (ms)",
			Default:   "100",
			AllowEdit: true,
			Validate: func(input string) error {
				_, err := strconv.Atoi(input)
				if err != nil {
					return errors.New("invalid latency")
				}

				return nil
			},
		}

		latencyRaw, err := latencyPrompt.Run()
		if err != nil {
			fmt.Printf("Prompt failed: %v\n", err)
			return
		}

		latencyInt, _ := strconv.Atoi(latencyRaw)
		latency = time.Duration(latencyInt) * time.Millisecond
	}

	servers, err := client.Servers(withLatency, latency)
	if err != nil {
		fmt.Printf("Error while getting PIA server list: %v", err)
		return
	}

	items := make([]string, 0)
	for _, r := range servers.Regions {
		items = append(items, r.Name)
	}

	serversPrompt := promptui.Select{
		Label: "Choose the server you need",
		Items: items,
	}

	i, _, err := serversPrompt.Run()
	if err != nil {
		fmt.Printf("Prompt failed: %v\n", err)
		return
	}

	config, err := client.CreateWireGuardConfig(username, password, servers.Regions[i].Servers)
	if err != nil {
		fmt.Println(strings.ToTitle(err.Error()))
	}

	fmt.Println("\n" + config)
}
