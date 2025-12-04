package main

import (
	"context"
	"fmt"
	"sync/atomic"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

//
// ============================================================================
//  OPTIMIZED IN-MEMORY STORE (dnsName → targetIP)
// ============================================================================
//  - atomic.Value provides lock-free reads
//  - updates replace the entire map atomically
//  - perfect for cases where reads >> writes
//

var endpointStore atomic.Value // holds map[string]string

// Must be called once early in main.go
func endpointStoreInit() {
	endpointStore.Store(make(map[string]string))
}

//
// ============================================================================
//  PUBLIC API
// ============================================================================

// GetDNSEntry returns (targetIP, exists)
func GetDNSEntry(domain string) (string, bool) {
	m := endpointStore.Load().(map[string]string)
	ip, ok := m[domain]
	return ip, ok
}

// Optional helper: return empty string if missing
func GetDNSEntryOrEmpty(domain string) string {
	m := endpointStore.Load().(map[string]string)
	return m[domain] // "" if not found
}

// Get a full immutable snapshot
func GetAllDNSEntries() map[string]string {
	return endpointStore.Load().(map[string]string)
}

//
// ============================================================================
//  INTERNAL HELPERS
// ============================================================================

// extractDNSEntries extracts dnsName → targetIP from a DNSEndpoint CRD
func extractDNSEntries(u *unstructured.Unstructured) map[string]string {
	result := make(map[string]string)

	spec, ok := u.Object["spec"].(map[string]interface{})
	if !ok {
		return result
	}

	endpoints, ok := spec["endpoints"].([]interface{})
	if !ok {
		return result
	}

	for _, ep := range endpoints {
		entry, ok := ep.(map[string]interface{})
		if !ok {
			continue
		}

		dnsName, _ := entry["dnsName"].(string)

		targets, ok := entry["targets"].([]interface{})
		if !ok || len(targets) == 0 {
			continue
		}

		// Assume one target per DNS name (ExternalDNS normal behavior)
		targetIP, _ := targets[0].(string)

		if dnsName != "" && targetIP != "" {
			result[dnsName] = targetIP
		}
	}

	return result
}

// applyUpdate merges extracted dnsName→IP entries into the store
func applyUpdate(update map[string]string) {
	current := endpointStore.Load().(map[string]string)

	next := make(map[string]string, len(current)+len(update))
	for k, v := range current {
		next[k] = v
	}
	for k, v := range update {
		next[k] = v
	}

	endpointStore.Store(next)
}

// applyDelete removes all dnsNames belonging to the deleted DNSEndpoint CRD
func applyDelete(u *unstructured.Unstructured) {
	toDelete := extractDNSEntries(u)
	current := endpointStore.Load().(map[string]string)

	next := make(map[string]string, len(current))
	for k, v := range current {
		if _, shouldDelete := toDelete[k]; !shouldDelete {
			next[k] = v
		}
	}

	endpointStore.Store(next)
}

//
// ============================================================================
//  WATCHER IMPLEMENTATION
// ============================================================================

func StartDNSEndpointWatcher(ctx context.Context) error {
	// Use service account credentials
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("failed to load in-cluster config: %w", err)
	}

	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("failed to create dynamic client: %w", err)
	}

	// CRD definition
	gvr := schema.GroupVersionResource{
		Group:    "externaldns.k8s.io",
		Version:  "v1alpha1",
		Resource: "dnsendpoints", // plural as required
	}

	factory := dynamicinformer.NewDynamicSharedInformerFactory(dyn, 0)
	informer := factory.ForResource(gvr).Informer()

	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{

		AddFunc: func(obj interface{}) {
			u := obj.(*unstructured.Unstructured)
			entries := extractDNSEntries(u)
			applyUpdate(entries)
			fmt.Println("[DNSEndpoint ADDED]", entries)
		},

		UpdateFunc: func(oldObj, newObj interface{}) {
			u := newObj.(*unstructured.Unstructured)
			entries := extractDNSEntries(u)
			applyUpdate(entries)
			fmt.Println("[DNSEndpoint UPDATED]", entries)
		},

		DeleteFunc: func(obj interface{}) {
			u := obj.(*unstructured.Unstructured)
			applyDelete(u)
			fmt.Println("[DNSEndpoint DELETED]")
		},
	})

	// Run asynchronously
	go factory.Start(ctx.Done())

	// Wait for initial cache sync
	if !cache.WaitForCacheSync(ctx.Done(), informer.HasSynced) {
		return fmt.Errorf("DNSEndpoint watcher cache failed to sync")
	}

	fmt.Println("[watcher] DNSEndpoint watcher is running")
	return nil
}
