package amneziawg

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

const maxConfigBytes = 8 << 20

// DecodeURI strips vpn://, accepts Qt qCompress (4-byte length + zlib) and
// raw JSON after base64url.
func DecodeURI(uri string) ([]byte, error) {
	s := strings.TrimSpace(uri)
	s = strings.TrimPrefix(s, "vpn://")
	if s == strings.TrimSpace(uri) {
		return nil, fmt.Errorf("vpn uri: missing vpn:// prefix")
	}
	raw, err := decodeBase64(s)
	if err != nil {
		return nil, fmt.Errorf("vpn uri: base64: %w", err)
	}
	if jsonBytes, ok := tryQCompress(raw); ok {
		return jsonBytes, nil
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') {
		return trimmed, nil
	}
	return nil, fmt.Errorf("vpn uri: payload is neither qCompress nor JSON")
}

func decodeBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	if raw, err := base64.URLEncoding.DecodeString(s); err == nil {
		return raw, nil
	}
	if raw, err := base64.StdEncoding.DecodeString(s); err == nil {
		return raw, nil
	}
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

func tryQCompress(raw []byte) ([]byte, bool) {
	if len(raw) < 5 {
		return nil, false
	}
	// Qt qCompress: 4-byte big-endian uncompressed length, then a zlib stream.
	n := int(binary.BigEndian.Uint32(raw[:4]))
	if n <= 0 || n > maxConfigBytes {
		return nil, false
	}
	zr, err := zlib.NewReader(bytes.NewReader(raw[4:]))
	if err != nil {
		return nil, false
	}
	defer func() { _ = zr.Close() }()
	out, err := io.ReadAll(io.LimitReader(zr, int64(n)+1))
	if err != nil || len(out) != n {
		return nil, false
	}
	trimmed := bytes.TrimSpace(out)
	if len(trimmed) == 0 || (trimmed[0] != '{' && trimmed[0] != '[') {
		return nil, false
	}
	return trimmed, true
}

// EncodeURI qCompresses jsonBody and returns a vpn:// link.
func EncodeURI(jsonBody []byte) string {
	return "vpn://" + base64.RawURLEncoding.EncodeToString(qCompress(jsonBody))
}

// EncodeRawJSON returns a vpn:// link whose payload is uncompressed JSON.
func EncodeRawJSON(jsonBody []byte) string {
	return "vpn://" + base64.RawURLEncoding.EncodeToString(jsonBody)
}

func qCompress(data []byte) []byte {
	var buf bytes.Buffer
	var hdr [4]byte
	hdr[0] = byte(len(data) >> 24)
	hdr[1] = byte(len(data) >> 16)
	hdr[2] = byte(len(data) >> 8)
	hdr[3] = byte(len(data))
	buf.Write(hdr[:])
	w := zlib.NewWriter(&buf)
	_, _ = w.Write(data)
	_ = w.Close()
	return buf.Bytes()
}

type envelope struct {
	Containers       []container `json:"containers"`
	DNS1             string      `json:"dns1"`
	DNS2             string      `json:"dns2"`
	HostName         string      `json:"hostName"`
	APIEndpoint      string      `json:"api_endpoint"`
	APIKey           string      `json:"api_key"`
	DefaultContainer string      `json:"defaultContainer"`
}

type container struct {
	Container string          `json:"container"`
	AWG       json.RawMessage `json:"awg"`
}

type awgBlock struct {
	LastConfig string `json:"last_config"`
	Port       any    `json:"port"`
}

// IsAPI reports whether the decoded JSON is an API link rather than a tunnel.
func IsAPI(doc []byte) (endpoint, key string, ok bool) {
	var env envelope
	if err := json.Unmarshal(doc, &env); err != nil {
		return "", "", false
	}
	if env.APIEndpoint == "" || env.APIKey == "" {
		return "", "", false
	}
	if _, found := findAWG(env); found {
		return "", "", false
	}
	return env.APIEndpoint, env.APIKey, true
}

func findAWG(env envelope) (awgBlock, bool) {
	var fallback awgBlock
	found := false
	for _, c := range env.Containers {
		if len(c.AWG) == 0 {
			continue
		}
		var block awgBlock
		if err := json.Unmarshal(c.AWG, &block); err != nil || block.LastConfig == "" {
			continue
		}
		if !found {
			fallback = block
			found = true
		}
		if env.DefaultContainer != "" && c.Container == env.DefaultContainer {
			return block, true
		}
		if strings.Contains(strings.ToLower(c.Container), "awg") {
			fallback = block
		}
	}
	return fallback, found
}
