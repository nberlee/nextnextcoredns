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

	log "github.com/sirupsen/logrus"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type Server struct {
	Pop    string `json:"pop"`
	Server string `json:"server"`
	IPv4   bool   `json:"ipv4"`
	IPv6   bool   `json:"ipv6"`
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

func main() {
	resp, _ := http.Get("https://router.nextdns.io/?source=ping")
	body, _ := io.ReadAll(resp.Body)

	var servers []Server
	json.Unmarshal(body, &servers)

	results := make([]Result, len(servers)*2)
	v6offset := len(servers)
	var fqdn string
	for j := 0; j < 3; j++ {
		for i, server := range servers {
			if server.IPv4 {
				fqdn = fmt.Sprintf("ipv4-%s.edge.nextdns.io", server.Server)
				url := fmt.Sprintf("https://%s/info", fqdn)
				rtt := checkServer(url)
				log.Infof("%s has a rtt of %d", fqdn, rtt)

				if j > 0 {
					results[i].rtt += rtt
				} else {
					results[i] = Result{server: fqdn, rtt: rtt}
				}
			}

			if server.IPv6 {
				v6index := i + v6offset
				fqdn = fmt.Sprintf("ipv6-%s.edge.nextdns.io", server.Server)
				url := fmt.Sprintf("https://%s/info", fqdn)
				rtt := checkServer(url)
				log.Infof("%s has a rtt of %d", fqdn, rtt)

				if j > 0 {
					results[v6index].rtt += rtt
				} else {
					results[v6index] = Result{server: fqdn, rtt: rtt}
				}
			}
		}
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].rtt < results[j].rtt
	})

	numResults := 0
	nextdnsResolvers := []net.IP{}
	for _, result := range results {
		if !isTLSSuccessful(result.server) {
			continue
		}

		lookup := dnsLookup(result.server)
		if lookup == nil {
			continue
		}

		nextdnsResolvers = append(nextdnsResolvers, lookup)
		numResults++

		if numResults == 4 {
			break
		}
	}
	log.Infof("NextDNS resolvers: %v", nextdnsResolvers)
	if numResults < 3 {
		log.Fatalf("Only found %d resolvers", numResults)
	}
	err := modifyCoreDNSConfigMap(nextdnsResolvers)
	if err != nil {
		log.Fatalf("Error modifying CoreDNS configmap: %v", err)
	}
}

func checkServer(url string) int {
	start := time.Now()
	resp, err := http.Get(url)
	if err != nil {
		log.Errorf("error get %s, error %v", url, err)
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

	return int(time.Since(start).Milliseconds()) + info.Rtt
}

// ksTLSSuccessful performs a TLS handshake with a given FQDN at port 853 and
// returns true if the handshake is successful and false otherwise.
func isTLSSuccessful(fqdn string) bool {
	conf := &tls.Config{
		InsecureSkipVerify: false, // Adjust as per your security needs
	}

	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:853", fqdn), conf)
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

func dnsLookup(fqdn string) net.IP {
	ips, err := net.LookupIP(fqdn)
	if err != nil {
		log.Errorf("Error: %v", err)
		return nil
	}

	return ips[0]
}

func modifyForwardLine(corefile string, ips []net.IP) string {
	lines := strings.Split(corefile, "\n")
	pattern := regexp.MustCompile(`^(\s*)(forward . (tls://[a-zA-Z0-9\.\[\]:]+:[0-9]+ ?)+({.*)?)$`)

	for i, line := range lines {

		if match := pattern.FindStringSubmatch(line); match != nil {
			// Replace the IP addresses in the forward line
			forwardLine := match[1] + "forward ."
			for _, ip := range ips {
				if ip.To4() == nil {
					// IPv6 address - add brackets
					forwardLine += " tls://[" + ip.String() + "]:853"
				} else {
					// IPv4 address
					forwardLine += " tls://" + ip.String() + ":853"
				}
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

func modifyCoreDNSConfigMap(ips []net.IP) error {
	var kubeClient kubernetes.Interface
	_, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalln("only in cluster config is supported")
	} else {
		kubeClient = getClient()
	}

	// Retrieve the CoreDNS ConfigMap in the current namespace
	kubeconfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(clientcmd.NewDefaultClientConfigLoadingRules(), &clientcmd.ConfigOverrides{})
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
func getClient() kubernetes.Interface {
	config, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalf("Can not get kubernetes config: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Can not create kubernetes client: %v", err)
	}

	return clientset
}
