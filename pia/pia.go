package pia

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"sort"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type ContextKey string

const (
	ctxResolve ContextKey = "resolve"
)

// TODO: In future releases of Go it's better to use brand-new go:embed comment directive
// More on: https://go.googlesource.com/proposal/+/master/design/draft-embed.md
const (
	serverListURL       = "https://serverlist.piaservers.net/vpninfo/servers/v4"
	serverListPublicKey = `-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzLYHwX5Ug/oUObZ5eH5P
rEwmfj4E/YEfSKLgFSsyRGGsVmmjiXBmSbX2s3xbj/ofuvYtkMkP/VPFHy9E/8ox
Y+cRjPzydxz46LPY7jpEw1NHZjOyTeUero5e1nkLhiQqO/cMVYmUnuVcuFfZyZvc
8Apx5fBrIp2oWpF/G9tpUZfUUJaaHiXDtuYP8o8VhYtyjuUu3h7rkQFoMxvuoOFH
6nkc0VQmBsHvCfq4T9v8gyiBtQRy543leapTBMT34mxVIQ4ReGLPVit/6sNLoGLb
gSnGe9Bk/a5V/5vlqeemWF0hgoRtUxMtU1hFbe7e8tSq1j+mu0SHMyKHiHd+OsmU
IQIDAQAB
-----END RSA PUBLIC KEY-----`
	piaCACertificate = `-----BEGIN CERTIFICATE-----
MIIHqzCCBZOgAwIBAgIJAJ0u+vODZJntMA0GCSqGSIb3DQEBDQUAMIHoMQswCQYD
VQQGEwJVUzELMAkGA1UECBMCQ0ExEzARBgNVBAcTCkxvc0FuZ2VsZXMxIDAeBgNV
BAoTF1ByaXZhdGUgSW50ZXJuZXQgQWNjZXNzMSAwHgYDVQQLExdQcml2YXRlIElu
dGVybmV0IEFjY2VzczEgMB4GA1UEAxMXUHJpdmF0ZSBJbnRlcm5ldCBBY2Nlc3Mx
IDAeBgNVBCkTF1ByaXZhdGUgSW50ZXJuZXQgQWNjZXNzMS8wLQYJKoZIhvcNAQkB
FiBzZWN1cmVAcHJpdmF0ZWludGVybmV0YWNjZXNzLmNvbTAeFw0xNDA0MTcxNzQw
MzNaFw0zNDA0MTIxNzQwMzNaMIHoMQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ0Ex
EzARBgNVBAcTCkxvc0FuZ2VsZXMxIDAeBgNVBAoTF1ByaXZhdGUgSW50ZXJuZXQg
QWNjZXNzMSAwHgYDVQQLExdQcml2YXRlIEludGVybmV0IEFjY2VzczEgMB4GA1UE
AxMXUHJpdmF0ZSBJbnRlcm5ldCBBY2Nlc3MxIDAeBgNVBCkTF1ByaXZhdGUgSW50
ZXJuZXQgQWNjZXNzMS8wLQYJKoZIhvcNAQkBFiBzZWN1cmVAcHJpdmF0ZWludGVy
bmV0YWNjZXNzLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALVk
hjumaqBbL8aSgj6xbX1QPTfTd1qHsAZd2B97m8Vw31c/2yQgZNf5qZY0+jOIHULN
De4R9TIvyBEbvnAg/OkPw8n/+ScgYOeH876VUXzjLDBnDb8DLr/+w9oVsuDeFJ9K
V2UFM1OYX0SnkHnrYAN2QLF98ESK4NCSU01h5zkcgmQ+qKSfA9Ny0/UpsKPBFqsQ
25NvjDWFhCpeqCHKUJ4Be27CDbSl7lAkBuHMPHJs8f8xPgAbHRXZOxVCpayZ2SND
fCwsnGWpWFoMGvdMbygngCn6jA/W1VSFOlRlfLuuGe7QFfDwA0jaLCxuWt/BgZyl
p7tAzYKR8lnWmtUCPm4+BtjyVDYtDCiGBD9Z4P13RFWvJHw5aapx/5W/CuvVyI7p
Kwvc2IT+KPxCUhH1XI8ca5RN3C9NoPJJf6qpg4g0rJH3aaWkoMRrYvQ+5PXXYUzj
tRHImghRGd/ydERYoAZXuGSbPkm9Y/p2X8unLcW+F0xpJD98+ZI+tzSsI99Zs5wi
jSUGYr9/j18KHFTMQ8n+1jauc5bCCegN27dPeKXNSZ5riXFL2XX6BkY68y58UaNz
meGMiUL9BOV1iV+PMb7B7PYs7oFLjAhh0EdyvfHkrh/ZV9BEhtFa7yXp8XR0J6vz
1YV9R6DYJmLjOEbhU8N0gc3tZm4Qz39lIIG6w3FDAgMBAAGjggFUMIIBUDAdBgNV
HQ4EFgQUrsRtyWJftjpdRM0+925Y6Cl08SUwggEfBgNVHSMEggEWMIIBEoAUrsRt
yWJftjpdRM0+925Y6Cl08SWhge6kgeswgegxCzAJBgNVBAYTAlVTMQswCQYDVQQI
EwJDQTETMBEGA1UEBxMKTG9zQW5nZWxlczEgMB4GA1UEChMXUHJpdmF0ZSBJbnRl
cm5ldCBBY2Nlc3MxIDAeBgNVBAsTF1ByaXZhdGUgSW50ZXJuZXQgQWNjZXNzMSAw
HgYDVQQDExdQcml2YXRlIEludGVybmV0IEFjY2VzczEgMB4GA1UEKRMXUHJpdmF0
ZSBJbnRlcm5ldCBBY2Nlc3MxLzAtBgkqhkiG9w0BCQEWIHNlY3VyZUBwcml2YXRl
aW50ZXJuZXRhY2Nlc3MuY29tggkAnS7684Nkme0wDAYDVR0TBAUwAwEB/zANBgkq
hkiG9w0BAQ0FAAOCAgEAJsfhsPk3r8kLXLxY+v+vHzbr4ufNtqnL9/1Uuf8NrsCt
pXAoyZ0YqfbkWx3NHTZ7OE9ZRhdMP/RqHQE1p4N4Sa1nZKhTKasV6KhHDqSCt/dv
Em89xWm2MVA7nyzQxVlHa9AkcBaemcXEiyT19XdpiXOP4Vhs+J1R5m8zQOxZlV1G
tF9vsXmJqWZpOVPmZ8f35BCsYPvv4yMewnrtAC8PFEK/bOPeYcKN50bol22QYaZu
LfpkHfNiFTnfMh8sl/ablPyNY7DUNiP5DRcMdIwmfGQxR5WEQoHL3yPJ42LkB5zs
6jIm26DGNXfwura/mi105+ENH1CaROtRYwkiHb08U6qLXXJz80mWJkT90nr8Asj3
5xN2cUppg74nG3YVav/38P48T56hG1NHbYF5uOCske19F6wi9maUoto/3vEr0rnX
JUp2KODmKdvBI7co245lHBABWikk8VfejQSlCtDBXn644ZMtAdoxKNfR2WTFVEwJ
iyd1Fzx0yujuiXDROLhISLQDRjVVAvawrAtLZWYK31bY7KlezPlQnl/D9Asxe85l
8jO5+0LdJ6VyOs/Hd4w52alDW/MFySDZSfQHMTIc30hLBJ8OnCEIvluVQQ2UQvoW
+no177N9L2Y+M9TcTA62ZyMXShHQGeh20rb4kK8f+iFX8NxtdHVSkxMEFSfDDyQ=
-----END CERTIFICATE-----`
)

func verifySignature(message, signature string) error {
	derBlock, _ := pem.Decode([]byte(serverListPublicKey))
	publicKey, err := x509.ParsePKIXPublicKey(derBlock.Bytes)
	if err != nil {
		return err
	}

	hasher := sha256.New()
	if _, err := hasher.Write([]byte(message)); err != nil {
		return err
	}
	hashed := hasher.Sum(nil)

	rawSignature, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return err
	}

	switch publicKey := publicKey.(type) {
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed, rawSignature); err != nil {
			return err
		}
	default:
		return errors.New("unknown public key type")
	}

	return nil
}

type Client struct {
	HTTPClient    *http.Client
	HTTPTransport *http.Transport
}

func NewClient() (*Client, error) {
	// New client
	httpClient := http.DefaultClient

	// New transport
	tr := http.DefaultTransport.(*http.Transport)

	// If UNIX, get system root CAs and append PIA root CA
	if runtime.GOOS != "windows" {
		p, err := x509.SystemCertPool()
		if err != nil {
			return nil, err
		}
		p.AppendCertsFromPEM([]byte(piaCACertificate))

		tr.TLSClientConfig = &tls.Config{
			RootCAs: p,
		}
	}

	// Custom dial context
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if value := ctx.Value(ctxResolve); value != nil {
			if value, ok := ctx.Value(ctxResolve).(string); !ok {
				return nil, errors.New("invalid input")
			} else {
				addr = value
			}
		}
		return dialer.DialContext(ctx, network, addr)
	}

	httpClient.Transport = tr
	return &Client{
		HTTPClient:    httpClient,
		HTTPTransport: tr,
	}, nil
}

// Servers returns structure with regions to connect;
// also supports withLatency option to calculate latency for each server and automatically sort them by it;
// set maxLatency to 0 to return all possible servers
func (c *Client) Servers(withLatency bool, maxLatency time.Duration) (*Servers, error) {
	resp, err := http.Get(serverListURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	parts := bytes.Split(b, []byte("\n\n"))
	if len(parts) != 2 {
		return nil, errors.New("invalid response")
	}

	if err := verifySignature(string(parts[0]), string(parts[1])); err != nil {
		return nil, err
	}

	var servers Servers
	if err := json.Unmarshal(parts[0], &servers); err != nil {
		return nil, err
	}

	if withLatency {
		// Wait group to sync goroutines
		var wg sync.WaitGroup
		// Channel to get result back
		regionsChan := make(chan *Region, len(servers.Regions))
		// Loop over regions to get latency
		for _, r := range servers.Regions {
			meta, ok := r.Servers["meta"]
			if !ok || len(meta) == 0 {
				continue
			}

			wg.Add(1)
			go func(r *Region) {
				defer wg.Done()

				now := time.Now()
				conn, err := net.DialTimeout("tcp", meta[0].IP.String()+":443", maxLatency)
				if err != nil {
					return
				}
				if err := conn.Close(); err != nil {
					return
				}

				l := time.Since(now)
				r.Latency = &l
				regionsChan <- r
			}(r)
		}

		// Wait when test ends
		wg.Wait()
		// ... and close channel to send signal
		close(regionsChan)

		regions := make([]*Region, 0, len(servers.Regions))
		for r := range regionsChan {
			regions = append(regions, r)
		}

		// Sort by latency (ascending)
		sort.Slice(regions, func(i, j int) bool {
			return regions[i].Latency.Nanoseconds() < regions[j].Latency.Nanoseconds()
		})

		servers.Regions = regions
	}

	return &servers, nil
}

func (c *Client) generateToken(username, password, commonName, ip string) (string, error) {
	u := &url.URL{
		Scheme: "https",
		User:   url.UserPassword(username, password),
		Host:   commonName,
		Path:   "/authv3/generateToken",
	}

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	req = req.WithContext(context.WithValue(context.Background(), ctxResolve, ip+":443"))

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var body struct {
		Status string `json:"status"`
		Token  string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", err
	}
	if body.Status != "OK" {
		return "", errors.New("invalid login or/and password")
	}

	return body.Token, nil
}

func (c *Client) addKey(token string, pubkey wgtypes.Key, commonName, ip string) (*AddedKey, error) {
	u := &url.URL{
		Scheme: "https",
		Host:   commonName + ":1337",
		Path:   "/addKey",
	}

	values := url.Values{}
	values.Set("pt", token)
	values.Set("pubkey", pubkey.String())

	u.RawQuery = values.Encode()

	req, err := http.NewRequest(http.MethodPost, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(context.WithValue(context.Background(), ctxResolve, ip+":1337"))

	addKeyResp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer addKeyResp.Body.Close()

	var body AddedKey
	if err := json.NewDecoder(addKeyResp.Body).Decode(&body); err != nil {
		return nil, err
	}
	if body.Status != "OK" {
		return nil, errors.New("something went wrong")
	}

	return &body, nil
}

func (c *Client) CreateWireGuardConfig(username, password string, servers map[string]Server) (string, error) {
	metaServer, ok := servers["meta"]
	if !ok || len(metaServer) <= 0 {
		return "", errors.New("there is no meta server")
	}

	wgServer, ok := servers["wg"]
	if !ok || len(metaServer) <= 0 {
		return "", errors.New("there is no wireguard server")
	}

	token, err := c.generateToken(username, password, metaServer[0].CommonName, metaServer[0].IP.String())
	if err != nil {
		return "", err
	}

	privkey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return "", nil
	}

	result, err := c.addKey(token, privkey.PublicKey(), wgServer[0].CommonName, wgServer[0].IP.String())
	if err != nil {
		return "", err
	}

	return fmt.Sprintf(
		`[Interface]
Address = %s
PrivateKey = %s
DNS = %s
[Peer]
PersistentKeepalive = 25
PublicKey = %s
AllowedIPs = 0.0.0.0/0
Endpoint = %s:%d`,
		result.PeerIP,
		privkey.String(),
		result.DNSServers[0],
		result.ServerKey,
		wgServer[0].IP.String(),
		result.ServerPort,
	), nil
}
