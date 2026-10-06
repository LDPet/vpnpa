package amneziawg

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/curve25519"
)

// KeyPair is a WireGuard X25519 identity. Private and Public are standard base64.
type KeyPair struct {
	Private string
	Public  string
	UUID    string
}

type storedKey struct {
	URIHash string `json:"uri_hash"`
	Private string `json:"private"`
	Public  string `json:"public"`
	UUID    string `json:"uuid"`
}

// GenerateKeyPair returns a clamped X25519 keypair and a random UUID.
func GenerateKeyPair() (KeyPair, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return KeyPair{}, err
	}
	priv[0] &= 248
	priv[31] = (priv[31] & 127) | 64
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return KeyPair{}, err
	}
	id, err := newUUID()
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPair{
		Private: base64.StdEncoding.EncodeToString(priv[:]),
		Public:  base64.StdEncoding.EncodeToString(pub),
		UUID:    id,
	}, nil
}

func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func uriHash(uri string) string {
	sum := sha256.Sum256([]byte(uri))
	return hex.EncodeToString(sum[:])
}

// loadOrCreateKey returns the keypair stored for id while uri is unchanged.
// A different uri replaces the file with a new keypair.
func loadOrCreateKey(dir, id, uri string) (KeyPair, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return KeyPair{}, err
	}
	path := filepath.Join(dir, id)
	hash := uriHash(uri)
	if raw, err := os.ReadFile(path); err == nil {
		var st storedKey
		if json.Unmarshal(raw, &st) == nil && st.URIHash == hash && st.Private != "" && st.Public != "" {
			if err := os.Chmod(path, 0o600); err != nil {
				return KeyPair{}, err
			}
			return KeyPair{Private: st.Private, Public: st.Public, UUID: st.UUID}, nil
		}
	}
	kp, err := GenerateKeyPair()
	if err != nil {
		return KeyPair{}, err
	}
	body, err := json.Marshal(storedKey{
		URIHash: hash,
		Private: kp.Private,
		Public:  kp.Public,
		UUID:    kp.UUID,
	})
	if err != nil {
		return KeyPair{}, err
	}
	if err := writeKeyFile(dir, path, body); err != nil {
		return KeyPair{}, err
	}
	return kp, nil
}

// writeKeyFile replaces path atomically so a crash cannot leave a torn key
// and rotate the public key on the next Up.
func writeKeyFile(dir, path string, body []byte) error {
	tmp, err := os.CreateTemp(dir, ".key-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	cleanup = false
	return os.Chmod(path, 0o600)
}
