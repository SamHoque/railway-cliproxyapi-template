package main

import (
	"bytes"
	"testing"
)

func TestSupportedDiscoveryBlockIsAcceptedAndStripped(t *testing.T) {
	proxyKey := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	managementKey := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	base := initialConfig(proxyKey, managementKey)
	input := append(append([]byte{}, base...), supportedDiscoveryBlock...)

	actual, err := reconcileConfig(input, proxyKey, managementKey)
	if err != nil {
		t.Fatalf("exact supported discovery block rejected: %v", err)
	}
	if !bytes.Equal(actual, base) {
		t.Fatalf("supported discovery defaults were not stripped from canonical config")
	}
}

func TestModifiedDiscoveryBlockFailsClosed(t *testing.T) {
	proxyKey := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	managementKey := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	modified := bytes.Replace(
		supportedDiscoveryBlock,
		[]byte("_ai-gateway._tcp"),
		[]byte("_changed._tcp"),
		1,
	)
	input := append(initialConfig(proxyKey, managementKey), modified...)

	if _, err := reconcileConfig(input, proxyKey, managementKey); err == nil {
		t.Fatal("modified discovery block was accepted")
	}
}

func TestDuplicateDiscoveryBlockFailsClosed(t *testing.T) {
	proxyKey := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	managementKey := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	input := append(initialConfig(proxyKey, managementKey), supportedDiscoveryBlock...)
	input = append(input, supportedDiscoveryBlock...)

	if _, err := reconcileConfig(input, proxyKey, managementKey); err == nil {
		t.Fatal("duplicate discovery block was accepted")
	}
}
