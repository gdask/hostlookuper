package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"sync/atomic"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

type DNSRotator struct {
	interval time.Duration     // how often to rotate
	stopCh   chan struct{}     // stop signal
	ipPool   []string          // IPs derived from subnet
	ipIndex  int64             // round-robin index
	dyn      dynamic.Interface // internal dynamic client

	gvr schema.GroupVersionResource // reference to DNSEndpoint CRD
}

//
// ============================================================================
//  INITIALIZATION
// ============================================================================
// subnet example: "10.1.1.0/24"
//

func NewDNSRotator(subnet string, interval time.Duration) (*DNSRotator, error) {
	// Parse the CIDR to generate available IPs
	_, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		return nil, fmt.Errorf("invalid subnet: %w", err)
	}

	ipPool := expandCIDR(ipnet)
	if len(ipPool) == 0 {
		return nil, fmt.Errorf("no usable IPs in subnet %s", subnet)
	}

	// Internal Kubernetes client (serviceaccount from Pod)
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load in-cluster config: %w", err)
	}

	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create dynamic client: %w", err)
	}

	rotator := &DNSRotator{
		interval: interval,
		stopCh:   make(chan struct{}),
		ipPool:   ipPool,
		ipIndex:  0,
		dyn:      dyn,
		gvr: schema.GroupVersionResource{
			Group:    "externaldns.k8s.io",
			Version:  "v1alpha1",
			Resource: "dnsendpoints",
		},
	}

	return rotator, nil
}

//
// Expand CIDR into usable IPs (excluding network + broadcast)
//

func expandCIDR(ipnet *net.IPNet) []string {
	var ips []string

	ip := ipnet.IP.To4()
	if ip == nil {
		return ips // IPv6 not handled unless you want it
	}

	network := ip.Mask(ipnet.Mask)
	broadcast := make(net.IP, len(network))
	for i := range network {
		broadcast[i] = network[i] | ^ipnet.Mask[i]
	}

	for cur := incIP(network); !cur.Equal(broadcast); cur = incIP(cur) {
		ips = append(ips, cur.String())
	}

	return ips
}

func incIP(ip net.IP) net.IP {
	res := make(net.IP, len(ip))
	copy(res, ip)

	for i := len(res) - 1; i >= 0; i-- {
		res[i]++
		if res[i] != 0 {
			break
		}
	}
	return res
}

//
// ============================================================================
//  START / STOP
// ============================================================================

func (r *DNSRotator) Start() {
	go func() {
		ticker := time.NewTicker(r.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				r.rotateOnce()
			case <-r.stopCh:
				fmt.Println("[rotator] stopping")
				return
			}
		}
	}()
}

func (r *DNSRotator) Stop() {
	close(r.stopCh)
}

//
// ============================================================================
//  ROTATION LOGIC
// ============================================================================

func (r *DNSRotator) pickRandomDomain() string {
	snapshot := GetAllDNSEntries() // map[dnsName]ip
	n := len(snapshot)
	if n == 0 {
		return ""
	}

	choice := rand.Intn(n)
	i := 0

	for domain := range snapshot {
		if i == choice {
			return domain
		}
		i++
	}
	return ""
}

func (r *DNSRotator) nextIP() string {
	if len(r.ipPool) == 0 {
		return ""
	}
	i := atomic.AddInt64(&r.ipIndex, 1)
	return r.ipPool[i%int64(len(r.ipPool))]
}

func (r *DNSRotator) rotateOnce() {
	domain := r.pickRandomDomain()
	if domain == "" {
		fmt.Println("[rotator] no domains to rotate")
		return
	}

	newIP := r.nextIP()
	if newIP == "" {
		fmt.Println("[rotator] no IPs available for rotation")
		return
	}

	fmt.Printf("[rotator] updating %s → %s\n", domain, newIP)

	if err := r.updateClusterCRD(domain, newIP); err != nil {
		fmt.Printf("[rotator] FAILED to update %s: %v\n", domain, err)
	}
}

//
// ============================================================================
//  PATCH CRD IN CLUSTER
// ============================================================================
// Since metadata.name == dnsName, we patch the CRD using domain name directly.
//

func (r *DNSRotator) updateClusterCRD(domain, newIP string) error {
	patch := map[string]interface{}{
		"spec": map[string]interface{}{
			"endpoints": []interface{}{
				map[string]interface{}{
					"dnsName":    domain,
					"recordType": "A",
					"targets":    []string{newIP},
				},
			},
		},
	}

	jsonPatch, err := json.Marshal(patch)
	if err != nil {
		return err
	}

	_, err = r.dyn.Resource(r.gvr).Namespace("default").Patch(
		context.Background(),
		domain,
		types.MergePatchType,
		jsonPatch,
		metav1.PatchOptions{},
	)

	return err
}
