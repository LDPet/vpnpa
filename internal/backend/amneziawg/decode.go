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

// maxConfigBytes ограничивает и распакованный qCompress, и тело ответа API.
// Длина из заголовка Qt не должна раздуть память.
const maxConfigBytes = 8 << 20

// DecodeURI снимает префикс vpn:// и возвращает JSON конверта.
//
// Полезная нагрузка — base64 (url, стандартный или raw, добивка '=' необязательна).
// Дальше два формата, которые кладёт клиент Amnezia:
//
//  1. Qt qCompress: 4 байта big-endian — длина несжатых данных, затем поток zlib.
//     Длина сверяется с фактическим выходом zlib, чтобы отсечь чужой поток.
//  2. Сырой JSON, если после base64 сразу '{' или '['. Так кодирует EncodeRawJSON.
//
// Это ещё не туннель: JSON может быть полным конфигом или ссылкой на API (см. IsAPI).
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

// tryQCompress узнаёт формат QByteArray::qCompress: длина несжатого тела
// и сразу за ней zlib (RFC 1950), не голый deflate. Чужой префикс из 4 байт
// не принимается, если zlib не сходится ровно в эту длину или это не JSON.
func tryQCompress(raw []byte) ([]byte, bool) {
	if len(raw) < 5 {
		return nil, false
	}
	// Qt qCompress: 4 байта big-endian — длина несжатых данных, затем поток zlib.
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

// EncodeURI сжимает jsonBody как qCompress и возвращает ссылку vpn://.
// Нужен тестам и симметрии с клиентом Amnezia; демон сам ссылки не выпускает.
func EncodeURI(jsonBody []byte) string {
	return "vpn://" + base64.RawURLEncoding.EncodeToString(qCompress(jsonBody))
}

// EncodeRawJSON возвращает vpn://, где после base64 лежит несжатый JSON.
// DecodeURI принимает и этот вид, не только qCompress.
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

// envelope — общий JSON и полной ссылки, и ответа API.
// Туннель лежит в containers[].awg.last_config. Поля api_* без такого блока —
// это ещё не туннель, а заявка на выдачу конфига.
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

// IsAPI отличает ссылку на API от уже готового туннеля.
// Нужны непустые api_endpoint и api_key и ни одного контейнера с awg.last_config.
// Если туннель уже вложен, поля API игнорируются: ходить за конфигом некуда и незачем.
// Возвращаемые endpoint и key не логируются.
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

// findAWG выбирает контейнер с last_config. Сначала точное имя defaultContainer,
// иначе контейнер, в имени которого есть "awg", иначе первый подходящий.
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
