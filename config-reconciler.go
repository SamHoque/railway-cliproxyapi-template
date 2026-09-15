package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

const (
	configName    = "config.yaml"
	maxConfigSize = 1 << 20
)

func fail(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "secure initialization failed")
		os.Exit(64)
	}
}

func validKey(value string) bool {
	if len(value) < 32 {
		return false
	}
	for _, char := range value {
		switch {
		case char >= 'A' && char <= 'Z':
		case char >= 'a' && char <= 'z':
		case char >= '0' && char <= '9':
		case strings.ContainsRune("._~-", char):
		default:
			return false
		}
	}
	lower := strings.ToLower(value)
	for _, prefix := range []string{
		"your-api-key", "your-secret-key", "change-me", "changeme", "default",
		"example", "test-key", "proxy-key", "management-key",
	} {
		if strings.HasPrefix(lower, prefix) {
			return false
		}
	}
	return true
}

func readSecretFIFO(path string, uid, gid int) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeNamedPipe == 0 || info.Mode().Perm() != 0600 {
		return "", errors.New("invalid secret handoff")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != uid || int(stat.Gid) != gid {
		return "", errors.New("invalid secret handoff owner")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	if err := os.Remove(path); err != nil {
		return "", err
	}
	deadline := time.Now().Add(5 * time.Second)
	data := make([]byte, 0, 257)
	buffer := make([]byte, 64)
	for time.Now().Before(deadline) {
		count, readErr := file.Read(buffer)
		if count > 0 {
			data = append(data, buffer[:count]...)
			if len(data) > 256 {
				return "", errors.New("secret handoff too large")
			}
			if bytes.Contains(data, []byte{'\n'}) {
				break
			}
		}
		if readErr != nil && !errors.Is(readErr, syscall.EAGAIN) && !errors.Is(readErr, io.EOF) {
			return "", readErr
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(data) < 2 || data[len(data)-1] != '\n' || bytes.Count(data, []byte{'\n'}) != 1 {
		return "", errors.New("incomplete secret handoff")
	}
	return string(data[:len(data)-1]), nil
}

func initialConfig(proxyKey, managementKey string) []byte {
	return renderConfig(proxyKey, managementKey, preservedConfig{debug: false})
}

type yamlNode struct {
	kind    string
	scalar  string
	mapping map[string]string
	order   []string
	list    []string
}

type strictConfig struct {
	nodes map[string]yamlNode
	order []string
}

type preservedConfig struct {
	debug               bool
	requestRetry        *int
	maxRetryCredentials *int
	maxRetryInterval    *int
}

var supportedDiscoveryBlock = []byte(
	"discovery:\n" +
		"  service-type: _ai-gateway._tcp\n" +
		"  subtypes:\n" +
		"    - _chat-completions\n" +
		"    - _responses\n" +
		"    - _messages\n" +
		"    - _generate-content\n" +
		"    - _interactions\n",
)

// stripSupportedDiscovery removes only the exact default block written by the
// v7.3.3 management API. The wrapper does not expose service discovery, and an
// absent block selects the same upstream defaults. Any changed or duplicate
// discovery block remains fail-closed instead of expanding the accepted YAML
// surface.
func stripSupportedDiscovery(input []byte) ([]byte, error) {
	marker := []byte("discovery:\n")
	if !bytes.Contains(input, marker) {
		return input, nil
	}
	if bytes.Count(input, marker) != 1 {
		return nil, errors.New("duplicate discovery block")
	}
	index := bytes.Index(input, marker)
	if index > 0 && input[index-1] != '\n' {
		return nil, errors.New("invalid discovery block position")
	}
	if !bytes.HasPrefix(input[index:], supportedDiscoveryBlock) {
		return nil, errors.New("unsupported discovery block")
	}
	end := index + len(supportedDiscoveryBlock)
	output := make([]byte, 0, len(input)-len(supportedDiscoveryBlock))
	output = append(output, input[:index]...)
	output = append(output, input[end:]...)
	return output, nil
}

func renderConfig(proxyKey, managementKey string, preserved preservedConfig) []byte {
	var output strings.Builder
	output.WriteString(
		"host: \"127.0.0.1\"\n" +
			"port: 8317\n" +
			"tls:\n" +
			"  enable: false\n" +
			"remote-management:\n" +
			"  allow-remote: true\n" +
			"  secret-key: \"" + managementKey + "\"\n" +
			"  disable-control-panel: false\n" +
			"  disable-auto-update-panel: true\n" +
			"auth-dir: \"/data/auth\"\n" +
			"api-keys:\n" +
			"  - \"" + proxyKey + "\"\n" +
			"debug: " + strconv.FormatBool(preserved.debug) + "\n" +
			"logging-to-file: false\n" +
			"usage-statistics-enabled: false\n" +
			"ws-auth: true\n",
	)
	for _, field := range []struct {
		name  string
		value *int
	}{
		{"request-retry", preserved.requestRetry},
		{"max-retry-credentials", preserved.maxRetryCredentials},
		{"max-retry-interval", preserved.maxRetryInterval},
	} {
		if field.value != nil {
			output.WriteString(field.name + ": " + strconv.Itoa(*field.value) + "\n")
		}
	}
	return []byte(output.String())
}

func validName(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range value {
		if !((char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-') {
			return false
		}
	}
	return true
}

func validScalarRune(char rune) bool {
	switch {
	case char >= 'A' && char <= 'Z':
		return true
	case char >= 'a' && char <= 'z':
		return true
	case char >= '0' && char <= '9':
		return true
	case strings.ContainsRune("._~/$+-", char):
		return true
	default:
		return false
	}
}

func parseScalar(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("empty scalar")
	}
	value := raw
	if strings.HasPrefix(raw, "\"") || strings.HasSuffix(raw, "\"") {
		if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
			return "", errors.New("ambiguous quote")
		}
		value = raw[1 : len(raw)-1]
		if value == "" {
			return "", errors.New("empty quoted scalar")
		}
	}
	for _, char := range value {
		if !validScalarRune(char) {
			return "", errors.New("unsupported scalar syntax")
		}
	}
	return value, nil
}

func splitMapping(line, prefix string) (string, string, bool) {
	if !strings.HasPrefix(line, prefix) {
		return "", "", false
	}
	body := strings.TrimPrefix(line, prefix)
	index := strings.Index(body, ":")
	if index <= 0 {
		return "", "", false
	}
	name := body[:index]
	if !validName(name) {
		return "", "", false
	}
	remainder := body[index+1:]
	if remainder == "" {
		return name, "", true
	}
	if !strings.HasPrefix(remainder, " ") || len(remainder) == 1 {
		return "", "", false
	}
	return name, remainder[1:], true
}

func parseStrictConfig(input []byte) (strictConfig, error) {
	if len(input) == 0 || len(input) > maxConfigSize || !utf8.Valid(input) {
		return strictConfig{}, errors.New("invalid config size or encoding")
	}
	if bytes.ContainsAny(input, "\r\t") || input[len(input)-1] != '\n' {
		return strictConfig{}, errors.New("invalid config encoding")
	}
	lines := strings.Split(string(input[:len(input)-1]), "\n")
	if len(lines) == 0 {
		return strictConfig{}, errors.New("empty config")
	}
	result := strictConfig{nodes: make(map[string]yamlNode)}

	for index := 0; index < len(lines); {
		line := lines[index]
		if line == "" || strings.HasPrefix(line, " ") || strings.HasSuffix(line, " ") {
			return strictConfig{}, errors.New("invalid top-level line")
		}
		name, raw, ok := splitMapping(line, "")
		if !ok {
			return strictConfig{}, errors.New("invalid top-level mapping")
		}
		if _, exists := result.nodes[name]; exists {
			return strictConfig{}, errors.New("duplicate top-level key")
		}
		result.order = append(result.order, name)
		index++

		if raw != "" {
			scalar, err := parseScalar(raw)
			if err != nil {
				return strictConfig{}, err
			}
			result.nodes[name] = yamlNode{kind: "scalar", scalar: scalar}
			continue
		}

		if index >= len(lines) || !strings.HasPrefix(lines[index], "  ") {
			return strictConfig{}, errors.New("empty mapping or list")
		}
		node := yamlNode{mapping: make(map[string]string)}
		for index < len(lines) && strings.HasPrefix(lines[index], "  ") {
			nested := lines[index]
			if strings.HasPrefix(nested, "   ") || strings.HasSuffix(nested, " ") {
				return strictConfig{}, errors.New("invalid nested indentation")
			}
			if strings.HasPrefix(nested, "  - ") {
				if node.kind == "mapping" {
					return strictConfig{}, errors.New("mixed mapping and list")
				}
				node.kind = "list"
				scalar, err := parseScalar(strings.TrimPrefix(nested, "  - "))
				if err != nil {
					return strictConfig{}, err
				}
				node.list = append(node.list, scalar)
				index++
				continue
			}
			if node.kind == "list" {
				return strictConfig{}, errors.New("mixed list and mapping")
			}
			node.kind = "mapping"
			nestedName, nestedRaw, ok := splitMapping(nested, "  ")
			if !ok || nestedRaw == "" {
				return strictConfig{}, errors.New("invalid nested mapping")
			}
			if _, exists := node.mapping[nestedName]; exists {
				return strictConfig{}, errors.New("duplicate nested key")
			}
			scalar, err := parseScalar(nestedRaw)
			if err != nil {
				return strictConfig{}, err
			}
			node.order = append(node.order, nestedName)
			node.mapping[nestedName] = scalar
			index++
		}
		result.nodes[name] = node
	}
	return result, nil
}

func equalOrder(actual, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}
	for index := range actual {
		if actual[index] != expected[index] {
			return false
		}
	}
	return true
}

func parseBoolScalar(node yamlNode) (bool, error) {
	if node.kind != "scalar" || (node.scalar != "true" && node.scalar != "false") {
		return false, errors.New("invalid boolean")
	}
	return node.scalar == "true", nil
}

func parseBoundedInt(node yamlNode) (*int, error) {
	if node.kind != "scalar" {
		return nil, errors.New("invalid integer")
	}
	value, err := strconv.Atoi(node.scalar)
	if err != nil || value < 0 || value > 100 {
		return nil, errors.New("integer outside allowed range")
	}
	return &value, nil
}

func validateStrictConfig(config strictConfig) (preservedConfig, error) {
	requiredOrder := []string{
		"host", "port", "tls", "remote-management", "auth-dir", "api-keys",
		"debug", "logging-to-file", "usage-statistics-enabled",
	}
	if len(config.order) < len(requiredOrder) ||
		!equalOrder(config.order[:len(requiredOrder)], requiredOrder) {
		return preservedConfig{}, errors.New("security field order drift")
	}

	allowedTop := map[string]bool{
		"host": true, "port": true, "tls": true, "remote-management": true,
		"auth-dir": true, "api-keys": true, "debug": true,
		"logging-to-file": true, "usage-statistics-enabled": true,
		"credential-concurrency": true, "credential-in-flight": true,
		"redis-usage-queue-retention-seconds": true, "ws-auth": true,
		"request-retry": true, "max-retry-credentials": true,
		"max-retry-interval": true,
	}
	for _, name := range config.order {
		if !allowedTop[name] {
			return preservedConfig{}, errors.New("unknown config field")
		}
	}

	for _, name := range []string{
		"host", "port", "auth-dir", "debug", "logging-to-file",
		"usage-statistics-enabled",
	} {
		if config.nodes[name].kind != "scalar" {
			return preservedConfig{}, errors.New("security scalar shape drift")
		}
	}
	tls := config.nodes["tls"]
	if tls.kind != "mapping" || !equalOrder(tls.order, []string{"enable"}) {
		return preservedConfig{}, errors.New("tls shape drift")
	}
	remote := config.nodes["remote-management"]
	if remote.kind != "mapping" || !equalOrder(remote.order, []string{
		"allow-remote", "secret-key", "disable-control-panel",
		"disable-auto-update-panel",
	}) {
		return preservedConfig{}, errors.New("remote-management shape drift")
	}
	apiKeys := config.nodes["api-keys"]
	if apiKeys.kind != "list" || len(apiKeys.list) != 1 {
		return preservedConfig{}, errors.New("api key cardinality drift")
	}

	knownMaps := map[string][]string{
		"credential-concurrency": {
			"cpa-heartbeat-timeout", "cpa-cancel-bound", "reclaim-grace",
			"cleanup-interval", "release-flush-interval", "release-max-backoff",
			"busy-retry-min", "busy-retry-max", "max-limit",
		},
		"credential-in-flight": {
			"snapshot-interval", "stale-after", "max-part-bytes",
			"max-part-count", "max-revision-bytes", "max-aggregate-groups",
			"max-details", "max-string-bytes", "staging-retention",
		},
	}
	for name, order := range knownMaps {
		if node, exists := config.nodes[name]; exists {
			if node.kind != "mapping" || !equalOrder(node.order, order) {
				return preservedConfig{}, errors.New("known mapping shape drift")
			}
		}
	}
	for _, name := range []string{
		"redis-usage-queue-retention-seconds", "ws-auth",
		"request-retry", "max-retry-credentials", "max-retry-interval",
	} {
		if node, exists := config.nodes[name]; exists && node.kind != "scalar" {
			return preservedConfig{}, errors.New("known scalar shape drift")
		}
	}

	debug, err := parseBoolScalar(config.nodes["debug"])
	if err != nil {
		return preservedConfig{}, err
	}
	preserved := preservedConfig{debug: debug}
	for name, target := range map[string]**int{
		"request-retry":         &preserved.requestRetry,
		"max-retry-credentials": &preserved.maxRetryCredentials,
		"max-retry-interval":    &preserved.maxRetryInterval,
	} {
		if node, exists := config.nodes[name]; exists {
			value, err := parseBoundedInt(node)
			if err != nil {
				return preservedConfig{}, err
			}
			*target = value
		}
	}
	return preserved, nil
}

func reconcileConfig(input []byte, proxyKey, managementKey string) ([]byte, error) {
	input, err := stripSupportedDiscovery(input)
	if err != nil {
		return nil, err
	}
	config, err := parseStrictConfig(input)
	if err != nil {
		return nil, err
	}
	preserved, err := validateStrictConfig(config)
	if err != nil {
		return nil, err
	}
	return renderConfig(proxyKey, managementKey, preserved), nil
}

func regularSecure(info *syscall.Stat_t, uid, gid int) bool {
	return info.Mode&syscall.S_IFMT == syscall.S_IFREG &&
		info.Mode&0777 == 0600 &&
		info.Uid == uint32(uid) &&
		info.Gid == uint32(gid) &&
		info.Nlink == 1
}

func directorySecure(info *syscall.Stat_t, uid, gid int) bool {
	return info.Mode&syscall.S_IFMT == syscall.S_IFDIR &&
		info.Mode&0777 == 0700 &&
		info.Uid == uint32(uid) &&
		info.Gid == uint32(gid)
}

func readExisting(dirFD, uid, gid int) ([]byte, bool, error) {
	fd, err := syscall.Openat(
		dirFD,
		configName,
		syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW,
		0,
	)
	if errors.Is(err, syscall.ENOENT) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	file := os.NewFile(uintptr(fd), configName)
	defer file.Close()

	var info syscall.Stat_t
	if err := syscall.Fstat(fd, &info); err != nil {
		return nil, false, err
	}
	if !regularSecure(&info, uid, gid) || info.Size <= 0 || info.Size > maxConfigSize {
		return nil, false, errors.New("unsafe config file")
	}
	content, err := io.ReadAll(io.LimitReader(file, maxConfigSize+1))
	if err != nil || len(content) > maxConfigSize {
		return nil, false, errors.New("invalid config file")
	}
	return content, true, nil
}

func writeAtomic(dirFD, uid, gid int, content []byte) error {
	tempName := ".config.yaml.tmp." + strconv.Itoa(os.Getpid())
	fd, err := syscall.Openat(
		dirFD,
		tempName,
		syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW,
		0600,
	)
	if err != nil {
		return err
	}
	temp := os.NewFile(uintptr(fd), tempName)
	ok := false
	defer func() {
		temp.Close()
		if !ok {
			syscall.Unlinkat(dirFD, tempName)
		}
	}()

	if err := syscall.Fchmod(fd, 0600); err != nil {
		return err
	}
	if err := syscall.Fchown(fd, uid, gid); err != nil {
		return err
	}
	if _, err := temp.Write(content); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := syscall.Renameat(dirFD, tempName, dirFD, configName); err != nil {
		return err
	}
	if err := syscall.Fsync(dirFD); err != nil {
		return err
	}
	ok = true
	return nil
}

func run() error {
	const uid, gid = 10001, 10001
	if os.Geteuid() != uid || len(os.Args) != 4 {
		return errors.New("invalid invocation")
	}
	proxyKey, err := readSecretFIFO(os.Args[2], uid, gid)
	if err != nil {
		return err
	}
	managementKey, err := readSecretFIFO(os.Args[3], uid, gid)
	if err != nil {
		return err
	}
	if !validKey(proxyKey) || !validKey(managementKey) || proxyKey == managementKey {
		return errors.New("invalid keys")
	}

	dirFD, err := syscall.Open(
		os.Args[1],
		syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return err
	}
	defer syscall.Close(dirFD)
	var dirInfo syscall.Stat_t
	if err := syscall.Fstat(dirFD, &dirInfo); err != nil {
		return err
	}
	if !directorySecure(&dirInfo, uid, gid) {
		return errors.New("unsafe state directory")
	}

	content, exists, err := readExisting(dirFD, uid, gid)
	if err != nil {
		return err
	}
	if !exists {
		content = initialConfig(proxyKey, managementKey)
	} else {
		content, err = reconcileConfig(content, proxyKey, managementKey)
		if err != nil {
			return err
		}
	}
	return writeAtomic(dirFD, uid, gid, content)
}

func main() {
	fail(run())
}
