package amneziawg

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	defaultOSVersion  = "linux"
	defaultAppVersion = "4.8.12.9"
)

type apiRequest struct {
	PublicKey  string `json:"public_key"`
	OSVersion  string `json:"os_version"`
	AppVersion string `json:"app_version"`
	UUID       string `json:"uuid"`
}

// httpClient is replaced in tests when they need a custom transport.
// Redirects are not followed: a vpn:// link must not move the API key to another host.
var httpClient = &http.Client{
	Timeout: 20 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func fetchAPIConfig(ctx context.Context, endpoint, apiKey string, kp KeyPair) ([]byte, error) {
	body, err := json.Marshal(apiRequest{
		PublicKey:  kp.Public,
		OSVersion:  defaultOSVersion,
		AppVersion: defaultAppVersion,
		UUID:       kp.UUID,
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Api-Key "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("api: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxConfigBytes))
	if err != nil {
		return nil, fmt.Errorf("api read: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("api status %d", resp.StatusCode)
	}
	return unwrapAPIBody(raw)
}

func unwrapAPIBody(raw []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(raw)
	if bytes.HasPrefix(trimmed, []byte("vpn://")) {
		return DecodeURI(string(trimmed))
	}
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, fmt.Errorf("api: unexpected body")
	}
	var wrap struct {
		Config string `json:"config"`
	}
	if err := json.Unmarshal(trimmed, &wrap); err != nil {
		return nil, fmt.Errorf("api json: %w", err)
	}
	if strings.TrimSpace(wrap.Config) == "" {
		// The body itself may already be the full envelope.
		var probe map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &probe); err != nil {
			return nil, fmt.Errorf("api json: %w", err)
		}
		if _, ok := probe["containers"]; ok {
			return trimmed, nil
		}
		return nil, fmt.Errorf("api: response has no config")
	}
	cfg := strings.TrimSpace(wrap.Config)
	if strings.HasPrefix(cfg, "vpn://") {
		return DecodeURI(cfg)
	}
	if strings.HasPrefix(cfg, "{") {
		return []byte(cfg), nil
	}
	decoded, err := DecodeURI("vpn://" + cfg)
	if err != nil {
		return nil, fmt.Errorf("api config: %w", err)
	}
	return decoded, nil
}
