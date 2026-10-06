package amneziawg

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Tunnel is the resolved userspace configuration. Key material is hex.
type Tunnel struct {
	Addresses              []netip.Addr
	DNS                    []netip.Addr
	MTU                    int
	PrivateKeyHex          string
	PublicKeyHex           string
	PresharedHex           string
	Endpoint               string
	AllowedIPs             []string
	PersistentKeepalive    string
	JC                     string
	Jmin                   string
	Jmax                   string
	S1                     string
	S2                     string
	S3                     string
	S4                     string
	H1                     string
	H2                     string
	H3                     string
	H4                     string
	I1                     string
	I2                     string
	I3                     string
	I4                     string
	I5                     string
	HeaderProtectionKeyHex string
	ContentPaddingAddition string
	RekeyAfterTime         string
	RekeyTimeout           string
	RejectAfterTime        string
	KeepaliveTimeout       string
	MaxHandshakeAttempts   string
	RandomTrailers         string
	DisableCookies         string
}

// ParseFullConfig turns a decoded full-config JSON document into a Tunnel.
// privateKey overrides $WIREGUARD_CLIENT_PRIVATE_KEY when set (API flow).
func ParseFullConfig(doc []byte, privateKey string) (Tunnel, error) {
	var env envelope
	if err := json.Unmarshal(doc, &env); err != nil {
		return Tunnel{}, fmt.Errorf("config json: %w", err)
	}
	block, ok := findAWG(env)
	if !ok {
		return Tunnel{}, fmt.Errorf("config json: no awg.last_config")
	}
	var last map[string]any
	if err := json.Unmarshal([]byte(block.LastConfig), &last); err != nil {
		return Tunnel{}, fmt.Errorf("last_config: %w", err)
	}
	text, _ := last["config"].(string)
	dns1 := firstString(env.DNS1, stringField(last, "dns1"))
	dns2 := firstString(env.DNS2, stringField(last, "dns2"))
	clientKey := firstString(privateKey, stringField(last, "client_priv_key"))
	text = applyPlaceholders(text, dns1, dns2, clientKey)
	fields := parseWG(text)

	fill := func(dst *string, keys ...string) {
		if strings.TrimSpace(*dst) != "" {
			return
		}
		for _, k := range keys {
			if v := fields.get(k); v != "" {
				*dst = v
				return
			}
			if v := stringField(last, k); v != "" {
				*dst = v
				return
			}
		}
	}

	var t Tunnel
	addrText := joinAll(fields.getAll("address"))
	if addrText == "" {
		addrText = stringField(last, "client_ip")
	}
	var err error
	t.Addresses, err = parseAddrs(addrText)
	if err != nil {
		return Tunnel{}, err
	}
	if len(t.Addresses) == 0 {
		return Tunnel{}, fmt.Errorf("config: address is empty")
	}

	dnsText := joinAll(fields.getAll("dns"))
	if dnsText == "" {
		dnsText = joinComma(dns1, dns2)
	}
	t.DNS, err = parseAddrs(dnsText)
	if err != nil {
		return Tunnel{}, fmt.Errorf("dns: %w", err)
	}

	mtuText := fields.get("mtu")
	if mtuText == "" {
		mtuText = stringField(last, "mtu")
	}
	t.MTU = 1280
	if mtuText != "" {
		n, err := strconv.Atoi(strings.TrimSpace(mtuText))
		if err != nil || n < 576 || n > 65535 {
			return Tunnel{}, fmt.Errorf("mtu: %q", mtuText)
		}
		t.MTU = n
	}

	priv := firstString(privateKey, fields.get("privatekey"), clientKey)
	if priv == "" {
		return Tunnel{}, fmt.Errorf("config: private key is empty")
	}
	t.PrivateKeyHex, err = keyToHex(priv)
	if err != nil {
		return Tunnel{}, fmt.Errorf("private key: %w", err)
	}
	pub := firstString(fields.get("publickey"), stringField(last, "server_pub_key"))
	if pub == "" {
		return Tunnel{}, fmt.Errorf("config: peer public key is empty")
	}
	t.PublicKeyHex, err = keyToHex(pub)
	if err != nil {
		return Tunnel{}, fmt.Errorf("public key: %w", err)
	}
	if psk := firstString(fields.get("presharedkey"), stringField(last, "psk_key"), stringField(last, "presharedkey")); psk != "" {
		t.PresharedHex, err = keyToHex(psk)
		if err != nil {
			return Tunnel{}, fmt.Errorf("preshared key: %w", err)
		}
	}
	// The conf text often omits AWG 3.1 fields; vpn:// keeps them on last_config.
	if hpk := firstString(fields.get("headerprotectionkey"), stringField(last, "headerprotectionkey")); hpk != "" {
		t.HeaderProtectionKeyHex, err = keyToHex(hpk)
		if err != nil {
			return Tunnel{}, fmt.Errorf("header protection key: %w", err)
		}
	}

	t.Endpoint = fields.get("endpoint")
	if t.Endpoint == "" {
		host := firstString(stringField(last, "hostName"), env.HostName)
		port := firstString(stringField(last, "port"), scalarString(block.Port))
		if host != "" && port != "" {
			t.Endpoint = hostPort(host, port)
		}
	}
	if t.Endpoint == "" {
		return Tunnel{}, fmt.Errorf("config: endpoint is empty")
	}

	for _, item := range fields.getAll("allowedips") {
		t.AllowedIPs = append(t.AllowedIPs, splitList(item)...)
	}
	if len(t.AllowedIPs) == 0 {
		if raw, ok := last["allowed_ips"]; ok {
			t.AllowedIPs = stringList(raw)
		}
	}
	if len(t.AllowedIPs) == 0 {
		t.AllowedIPs = []string{"0.0.0.0/0"}
	}

	fill(&t.PersistentKeepalive, "persistentkeepalive", "persistent_keep_alive")
	fill(&t.JC, "jc")
	fill(&t.Jmin, "jmin")
	fill(&t.Jmax, "jmax")
	fill(&t.S1, "s1")
	fill(&t.S2, "s2")
	fill(&t.S3, "s3")
	fill(&t.S4, "s4")
	fill(&t.H1, "h1")
	fill(&t.H2, "h2")
	fill(&t.H3, "h3")
	fill(&t.H4, "h4")
	fill(&t.I1, "i1")
	fill(&t.I2, "i2")
	fill(&t.I3, "i3")
	fill(&t.I4, "i4")
	fill(&t.I5, "i5")
	fill(&t.ContentPaddingAddition, "contentpaddingaddition", "content_padding_addition")
	fill(&t.RekeyAfterTime, "rekeyaftertime", "rekey_after_time")
	fill(&t.RekeyTimeout, "rekeytimeout", "rekey_timeout")
	fill(&t.RejectAfterTime, "rejectaftertime", "reject_after_time")
	fill(&t.KeepaliveTimeout, "keepalivetimeout", "keepalive_timeout")
	fill(&t.MaxHandshakeAttempts, "maxhandshakeattempts", "max_handshake_attempts")
	fill(&t.RandomTrailers, "randomtrailers", "random_trailers")
	fill(&t.DisableCookies, "disablecookies", "disable_cookies")
	t.RandomTrailers = normalizeBool(t.RandomTrailers)
	t.DisableCookies = normalizeBool(t.DisableCookies)
	return t, nil
}

func applyPlaceholders(text, dns1, dns2, clientKey string) string {
	repl := []struct{ old, new string }{
		{"$PRIMARY_DNS", dns1},
		{"$SECONDARY_DNS", dns2},
	}
	if strings.Contains(text, "$WIREGUARD_CLIENT_PRIVATE_KEY") && clientKey != "" {
		repl = append(repl, struct{ old, new string }{"$WIREGUARD_CLIENT_PRIVATE_KEY", clientKey})
	}
	for _, r := range repl {
		text = strings.ReplaceAll(text, r.old, r.new)
	}
	return text
}

type wgFields struct {
	vals map[string][]string
}

func (f wgFields) get(key string) string {
	all := f.vals[normalizeKey(key)]
	if len(all) == 0 {
		return ""
	}
	return all[len(all)-1]
}

func (f wgFields) getAll(key string) []string {
	return f.vals[normalizeKey(key)]
}

func parseWG(text string) wgFields {
	f := wgFields{vals: map[string][]string{}}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
			continue
		}
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = normalizeKey(key)
		val = strings.Trim(strings.TrimSpace(val), `"'`)
		f.vals[key] = append(f.vals[key], val)
	}
	return f
}

func normalizeKey(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "_", "")
	s = strings.ReplaceAll(s, "-", "")
	return s
}

func stringField(m map[string]any, key string) string {
	want := normalizeKey(key)
	for k, v := range m {
		if normalizeKey(k) == want {
			return scalarString(v)
		}
	}
	return ""
}

func scalarString(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case json.Number:
		return t.String()
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}

func stringList(v any) []string {
	switch t := v.(type) {
	case []any:
		var out []string
		for _, item := range t {
			if s := scalarString(item); s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		return splitList(t)
	default:
		return nil
	}
}

func splitList(s string) []string {
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseAddrs(s string) ([]netip.Addr, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var out []netip.Addr
	for _, part := range splitList(s) {
		part = strings.TrimSpace(part)
		if i := strings.IndexByte(part, '/'); i >= 0 {
			pfx, err := netip.ParsePrefix(part)
			if err != nil {
				return nil, fmt.Errorf("address %q: %w", part, err)
			}
			out = append(out, pfx.Addr())
			continue
		}
		addr, err := netip.ParseAddr(part)
		if err != nil {
			return nil, fmt.Errorf("address %q: %w", part, err)
		}
		out = append(out, addr)
	}
	return out, nil
}

func keyToHex(s string) (string, error) {
	s = strings.TrimSpace(s)
	if len(s) == 64 && isHex(s) {
		return strings.ToLower(s), nil
	}
	raw, err := decodeKey(s)
	if err != nil {
		return "", err
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("key length %d", len(raw))
	}
	return hex.EncodeToString(raw), nil
}

func decodeKey(s string) ([]byte, error) {
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	if raw, err := base64.StdEncoding.DecodeString(s); err == nil {
		return raw, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

func isHex(s string) bool {
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

func firstString(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func joinAll(vals []string) string {
	var parts []string
	for _, v := range vals {
		parts = append(parts, splitList(v)...)
	}
	return strings.Join(parts, ", ")
}

func joinComma(a, b string) string {
	switch {
	case a != "" && b != "":
		return a + ", " + b
	case a != "":
		return a
	default:
		return b
	}
}

func hostPort(host, port string) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return host + ":" + port
}

func normalizeBool(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return ""
	case "1", "t", "true", "on", "yes":
		return "true"
	case "0", "f", "false", "off", "no":
		return "false"
	default:
		return strings.TrimSpace(s)
	}
}

// TrailersRangeWarning reports the amneziawg-go issue combination:
// RandomTrailers enabled together with ranged H1, H2 and H3.
func TrailersRangeWarning(t Tunnel) bool {
	if t.RandomTrailers != "true" {
		return false
	}
	return isRange(t.H1) && isRange(t.H2) && isRange(t.H3)
}

func isRange(v string) bool {
	left, right, ok := strings.Cut(strings.TrimSpace(v), "-")
	if !ok {
		return false
	}
	return left != "" && right != "" && !strings.Contains(right, "-")
}
