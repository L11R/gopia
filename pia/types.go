package pia

import (
	"net"
	"time"
)

type Servers struct {
	Groups  map[string]Group `json:"groups"`
	Regions []*Region        `json:"regions"`
}

type Group []struct {
	Name  string `json:"name"`
	Ports []int  `json:"ports"`
}

type Region struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Country        string            `json:"country"`
	AutoRegion     bool              `json:"auto_region"`
	DNS            string            `json:"dns"`
	PortForwarding bool              `json:"port_forward"`
	Geo            bool              `json:"geo"`
	Servers        map[string]Server `json:"servers"`
	Latency        *time.Duration     `json:"latency"`
}

type Server []struct {
	IP         net.IP `json:"ip"`
	CommonName string `json:"cn"`
}

type AddedKey struct {
	Status          string   `json:"status"`
	ServerKey       string   `json:"server_key"`
	ServerPort      int      `json:"server_port"`
	ServerIP        string   `json:"server_ip"`
	ServerVirtualIP string   `json:"server_vip"`
	PeerIP          string   `json:"peer_ip"`
	PeerPublicKey   string   `json:"peer_pubkey"`
	DNSServers      []string `json:"dns_servers"`
}