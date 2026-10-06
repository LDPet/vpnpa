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

// apiRequest — тело POST, которым клиент Amnezia представляется серверу.
// Сервер выдаёт туннель на PublicKey; смена ключа при том же URI была бы новым клиентом.
type apiRequest struct {
	PublicKey  string `json:"public_key"`
	OSVersion  string `json:"os_version"`
	AppVersion string `json:"app_version"`
	UUID       string `json:"uuid"`
}

// httpClient вынесен переменной. Текущие тесты ходят им в httptest и не подменяют его.
// Редиректы не следуются: ссылка vpn:// не должна унести API-ключ на другой хост.
var httpClient = &http.Client{
	Timeout: 20 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// fetchAPIConfig забирает полный конфиг по ссылке API.
// Ключ передаётся заголовком Authorization: Api-Key, не в URL.
// Ответ ограничен maxConfigBytes и дальше разбирается unwrapAPIBody.
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

// unwrapAPIBody приводит разные формы ответа API к JSON конверта.
// Встречаются: голое тело vpn://, JSON с полем config (vpn://, голый JSON
// или base64 без префикса) и уже готовый конверт с containers.
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
		// Тело само может уже быть полным конвертом, без обёртки config.
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
