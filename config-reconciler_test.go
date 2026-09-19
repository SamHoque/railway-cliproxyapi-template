package main

import (
	"bytes"
	"strings"
	"testing"
)

const defaultDiscoveryBlock = "discovery:\n" +
	"  service-type: _ai-gateway._tcp\n" +
	"  subtypes:\n" +
	"    - _chat-completions\n" +
	"    - _responses\n" +
	"    - _messages\n" +
	"    - _generate-content\n" +
	"    - _interactions\n"

func configWithoutDiscovery(proxyKey, managementKey string) []byte {
	return renderConfig(proxyKey, managementKey, preservedConfig{debug: false})
}

func TestInitialConfigIncludesUpstreamDiscoveryDefaults(t *testing.T) {
	config := initialConfig(
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	)
	if !bytes.Contains(config, []byte(defaultDiscoveryBlock)) {
		t.Fatal("initial config omitted upstream discovery defaults")
	}
}

func TestLegacyConfigMigratesToUpstreamDiscoveryDefaults(t *testing.T) {
	proxyKey := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	managementKey := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	legacy := configWithoutDiscovery(proxyKey, managementKey)

	actual, err := reconcileConfig(legacy, proxyKey, managementKey)
	if err != nil {
		t.Fatalf("legacy config migration failed: %v", err)
	}
	if !bytes.Contains(actual, []byte(defaultDiscoveryBlock)) {
		t.Fatal("legacy config did not gain upstream discovery defaults")
	}
}

func TestSupportedDiscoveryDefaultsRoundTrip(t *testing.T) {
	proxyKey := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	managementKey := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	input := append(configWithoutDiscovery(proxyKey, managementKey), []byte(defaultDiscoveryBlock)...)

	actual, err := reconcileConfig(input, proxyKey, managementKey)
	if err != nil {
		t.Fatalf("exact upstream discovery defaults rejected: %v", err)
	}
	if !bytes.Equal(actual, input) {
		t.Fatal("upstream discovery defaults were not round-tripped")
	}
}

func TestEnabledCustomDiscoveryRoundTrips(t *testing.T) {
	proxyKey := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	managementKey := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	discovery := "discovery:\n" +
		"  enabled: true\n" +
		"  service-type: _cliproxy._tcp\n" +
		"  subtypes:\n" +
		"    - _responses\n" +
		"    - _messages\n"
	input := append(configWithoutDiscovery(proxyKey, managementKey), []byte(discovery)...)

	actual, err := reconcileConfig(input, proxyKey, managementKey)
	if err != nil {
		t.Fatalf("valid enabled discovery config rejected: %v", err)
	}
	if !bytes.Equal(actual, input) {
		t.Fatal("enabled discovery config was not round-tripped")
	}
}

func TestV738ManagementRewriteDefaultsAreAccepted(t *testing.T) {
	proxyKey := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	managementKey := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	base := strings.Replace(
		string(configWithoutDiscovery(proxyKey, managementKey)),
		"debug: false\n", "debug: true\n", 1,
	)
	input := []byte(base +
		"credential-concurrency:\n" +
		"  cpa-heartbeat-timeout: 3s\n" +
		"  cpa-cancel-bound: 5s\n" +
		"  reclaim-grace: 5s\n" +
		"  cleanup-interval: 5s\n" +
		"  release-flush-interval: 250ms\n" +
		"  release-max-backoff: 2s\n" +
		"  busy-retry-min: 250ms\n" +
		"  busy-retry-max: 1s\n" +
		"  max-limit: 1000000\n" +
		"credential-in-flight:\n" +
		"  snapshot-interval: 2s\n" +
		"  stale-after: 10s\n" +
		"  max-part-bytes: 262144\n" +
		"  max-part-count: 64\n" +
		"  max-revision-bytes: 16777216\n" +
		"  max-aggregate-groups: 100000\n" +
		"  max-details: 10000\n" +
		"  max-string-bytes: 256\n" +
		"  staging-retention: 1m\n" +
		defaultDiscoveryBlock +
		"redis-usage-queue-retention-seconds: 60\n" +
		"disable-cooling: false\n" +
		"request-retry: 3\n" +
		"max-retry-credentials: 3\n" +
		"max-retry-interval: 3\n")

	actual, err := reconcileConfig(input, proxyKey, managementKey)
	if err != nil {
		t.Fatalf("v7.3.8 management rewrite defaults rejected: %v", err)
	}
	for _, want := range []string{
		"debug: true\n", "request-retry: 3\n",
		"max-retry-credentials: 3\n", "max-retry-interval: 3\n",
		defaultDiscoveryBlock,
	} {
		if !bytes.Contains(actual, []byte(want)) {
			t.Fatalf("reconciled config omitted preserved setting %q", want)
		}
	}
}

func TestUnsafeDiscoveryConfigsFailClosed(t *testing.T) {
	proxyKey := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	managementKey := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	base := configWithoutDiscovery(proxyKey, managementKey)
	tests := map[string]string{
		"invalid service type": strings.Replace(
			defaultDiscoveryBlock, "_ai-gateway._tcp", "_ai_gateway._tcp", 1,
		),
		"invalid enabled flag": strings.Replace(
			defaultDiscoveryBlock, "discovery:\n", "discovery:\n  enabled: yes\n", 1,
		),
		"unknown nested field": strings.Replace(
			defaultDiscoveryBlock, "  service-type:", "  advertise-management: true\n  service-type:", 1,
		),
		"duplicate subtype": strings.Replace(
			defaultDiscoveryBlock, "    - _responses\n", "    - _responses\n    - _responses\n", 1,
		),
		"empty subtype list": "discovery:\n  service-type: _ai-gateway._tcp\n  subtypes:\n",
		"nested mapping injection": strings.Replace(
			defaultDiscoveryBlock, "  subtypes:\n", "  subtypes:\n    interfaces:\n", 1,
		),
	}
	for name, discovery := range tests {
		t.Run(name, func(t *testing.T) {
			input := append(append([]byte{}, base...), []byte(discovery)...)
			if _, err := reconcileConfig(input, proxyKey, managementKey); err == nil {
				t.Fatal("unsafe discovery config was accepted")
			}
		})
	}
}

func TestDuplicateDiscoveryBlockFailsClosed(t *testing.T) {
	proxyKey := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	managementKey := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	input := append(configWithoutDiscovery(proxyKey, managementKey), []byte(defaultDiscoveryBlock)...)
	input = append(input, []byte(defaultDiscoveryBlock)...)

	if _, err := reconcileConfig(input, proxyKey, managementKey); err == nil {
		t.Fatal("duplicate discovery block was accepted")
	}
}
