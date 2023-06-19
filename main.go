package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/babolivier/go-doh-client"

	log "github.com/sirupsen/logrus"
	_ "go.uber.org/automaxprocs"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type Server struct {
	Hostname string   `json:"hostname"`
	IPs      []string `json:"ips"`
}

type Info struct {
	LocationName string `json:"locationName"`
	Pop          string `json:"pop"`
	Rtt          int    `json:"rtt"`
}

type Result struct {
	server string
	rtt    int
}

func getNextDNSRouterIps() []Result {

	dohResolver := doh.Resolver{
		Host: "45.90.28.0",
		HTTPClient: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				MaxIdleConnsPerHost: -1,
				TLSClientConfig:     &tls.Config{ServerName: "dns.nextdns.io"},
			},
		},

		Class: doh.IN,
	}

	// Create a custom transport with a modified Dial function
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName: "router.nextdns.io",
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Create a custom dialer with the modified DNS resolver
			dialer := &net.Dialer{
				Timeout:   30 * time.Second,
				DualStack: true,
			}

			if strings.HasSuffix(network, "6") {
				record, _, err := dohResolver.LookupAAAA("router.nextdns.io")
				if err != nil {
					log.Fatalf("Error resolving router.nextdns.io: %v", err)
				}
				if len(record) == 0 {
					log.Fatalf("Error resolving router.nextdns.io: no AAAA record")
				}
				addr = strings.Replace(addr, "router.nextdns.io", record[0].IP6, 1)
			} else {
				record, _, err := dohResolver.LookupA("router.nextdns.io")
				if err != nil {
					log.Fatalf("Error resolving router.nextdns.io: %v", err)
				}
				if len(record) == 0 {
					log.Fatalf("Error resolving router.nextdns.io: no A record")
				}
				addr = strings.Replace(addr, "router.nextdns.io", record[0].IP4, 1)
			}
			// If resolution fails, fallback to default resolver
			return dialer.DialContext(ctx, network, addr)
		},
	}

	client := &http.Client{
		Transport: transport,
	}

	resp, err := client.Get("https://router.nextdns.io/?limit=20&stack=dual")
	if err != nil {
		log.Fatalf("Error while contacting router.nextdns.io: %v", err)
	}
	defer resp.Body.Close()

	// Process the response
	body, _ := io.ReadAll(resp.Body)
	var servers []Server
	var results []Result
	json.Unmarshal(body, &servers)

	for j := 0; j < 3; j++ {
		count := 0
		for _, server := range servers {
			for _, ip := range server.IPs {
				if strings.Contains(ip, ":") {
					ip = "[" + ip + "]"
				}
				rtt := checkServer(ip)
				log.Infof("%s with ip %s has a rtt of %d", server.Hostname, ip, rtt)

				if j > 0 {
					results[count].rtt += rtt
				} else {
					results = append(results, Result{server: ip, rtt: rtt})
				}
				count++
			}
		}
	}
	return results
}

func main() {

	results := getNextDNSRouterIps()

	sort.Slice(results, func(i, j int) bool {
		return results[i].rtt < results[j].rtt
	})

	numResults := 0
	var nextdnsResolvers []string
	for _, result := range results {
		if !isTLSSuccessful(result.server) {
			continue
		}

		log.Infof("Selected %s with total rtt %d", result.server, result.rtt)
		nextdnsResolvers = append(nextdnsResolvers, result.server)
		numResults++

		if numResults == 4 {
			break
		}
	}
	log.Infof("NextDNS resolvers (ip): %v", nextdnsResolvers)
	if numResults < 3 {
		log.Fatalf("Only found %d resolvers", numResults)
	}
	err := modifyCoreDNSConfigMap(nextdnsResolvers)
	if err != nil {
		log.Fatalf("Error modifying CoreDNS configmap: %v", err)
	}
}

func checkServer(ip string) int {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{ServerName: "dns.nextdns.io"},
			MaxIdleConnsPerHost: -1,
		},
		Timeout: 1 * time.Second,
	}
	resp, err := client.Get("https://" + ip + "/info")

	if err != nil {
		log.Errorf("error get %s, error %v", ip, err)
		return 99999999
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("reading body error %v", err)
		return 99999999
	}

	var info Info
	err = json.Unmarshal(body, &info)
	if err != nil {
		log.Errorf("error unmarshalling %s, error %v", body, err)
		return 99999999
	}

	return info.Rtt
}

// ksTLSSuccessful performs a TLS handshake with a given FQDN at port 853 and
// returns true if the handshake is successful and false otherwise.
func isTLSSuccessful(ip string) bool {
	conf := &tls.Config{
		ServerName: "dns.nextdns.io",
	}

	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:853", ip), conf)
	if err != nil {
		log.Errorf("Failed to establish connection: %v", err)
		return false
	}
	defer conn.Close()

	err = conn.Handshake()
	if err != nil {
		log.Errorf("Failed to complete TLS handshake: %v", err)
		return false
	}

	return true
}

func modifyForwardLine(corefile string, ips []string) string {
	lines := strings.Split(corefile, "\n")
	pattern := regexp.MustCompile(`^(\s*)(forward . (tls://[a-zA-Z0-9\.\[\]:]+:[0-9]+ ?)+({.*)?)$`)

	for i, line := range lines {

		if match := pattern.FindStringSubmatch(line); match != nil {
			// Replace the IP addresses in the forward line
			forwardLine := match[1] + "forward ."
			for _, ip := range ips {
				forwardLine += " tls://" + ip + ":853"
			}

			if strings.HasPrefix(match[len(match)-1], "{") {
				forwardLine += " " + match[len(match)-1]
			}
			lines[i] = forwardLine
			break
		}
	}
	return strings.Join(lines, "\n")
}

func modifyCoreDNSConfigMap(ips []string) error {
	var kubeClient kubernetes.Interface
	var kubeconfig clientcmd.ClientConfig
	inClusterConfig, err := rest.InClusterConfig()

	if err != nil {
		loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
		configOverrides := &clientcmd.ConfigOverrides{}
		kubeconfig = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)

		config, err := kubeconfig.ClientConfig()
		if err != nil {
			log.Fatalf("Failed to load kubeconfig: %v", err)
		}
		kubeClient, err = kubernetes.NewForConfig(config)
		if err != nil {
			log.Fatalf("Failed to create Kubernetes client with kubeconfig: %v", err)
		}
	} else {
		kubeClient, err = kubernetes.NewForConfig(inClusterConfig)
		if err != nil {
			log.Fatalf("Failed to create Kubernetes client with in-cluster config: %v", err)
		}
		kubeconfig = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(clientcmd.NewDefaultClientConfigLoadingRules(), &clientcmd.ConfigOverrides{})
	}

	// Retrieve the CoreDNS ConfigMap in the current namespace
	namespace, _, err := kubeconfig.Namespace()
	if err != nil {
		namespace = metav1.NamespaceDefault
	}
	configMapName := "coredns"
	configMap, err := kubeClient.CoreV1().ConfigMaps(namespace).Get(context.TODO(), configMapName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to retrieve ConfigMap %s: %v", configMapName, err)
	}

	// Modify the "forward ." line in the Corefile with the new IP addresses
	corefile := configMap.Data["Corefile"]
	newCorefile := modifyForwardLine(corefile, ips)

	if corefile == newCorefile {
		// No changes to the Corefile
		log.Info("No changes to the Corefile")
		return nil
	}

	configMap.Data["Corefile"] = newCorefile

	// Update the ConfigMap
	_, err = kubeClient.CoreV1().ConfigMaps(namespace).Update(context.TODO(), configMap, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update ConfigMap %s: %v", configMapName, err)
	}

	log.Infof("Modified ConfigMap %s/%s successfully", namespace, configMapName)
	return nil
}
