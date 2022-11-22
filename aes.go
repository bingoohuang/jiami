package jiami

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

type Plain struct {
	// Required
	Data []byte

	// Optional
	Salt           []byte
	IV             []byte
	AdditionalData []byte
}

type Encoded struct {
	Salt []byte
	IV   []byte
	Data []byte
}

type Key struct {
	Passphrase []byte
	Key        []byte
	Salt       []byte
}

func (k *Key) Init() error {
	if len(k.Key) > 0 {
		return nil
	}

	if len(k.Passphrase) == 0 {
		return fmt.Errorf("one of passphrase and key should be specified")
	}

	if len(k.Salt) == 0 {
		k.Salt = make([]byte, 8)
		// http://www.ietf.org/rfc/rfc2898.txt
		rand.Read(k.Salt)
	}

	// 32 bit key for AES-256
	// 24 bit key for AES-192
	// 16 bit key for AES-128
	k.Key = pbkdf2.Key(k.Passphrase, k.Salt, 1000, 32, sha256.New)
	return nil
}

type AesGcm struct{}

func NewAesGcm() *AesGcm { return &AesGcm{} }

func (*AesGcm) Encrypt(key *Key, in *Plain) (*Encoded, error) {
	out := &Encoded{Salt: key.Salt}

	if len(in.IV) == 0 {
		in.IV = make([]byte, 12)
		// http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
		// Section 8.2
		rand.Read(in.IV)
	}
	out.IV = in.IV

	b, err := aes.NewCipher(key.Key)
	if err != nil {
		return nil, fmt.Errorf("aes NewCipher failed: %w", err)
	}
	gcm, err := cipher.NewGCM(b)
	if err != nil {
		return nil, fmt.Errorf("cipher NewGCM failed: %w", err)
	}

	out.Data = gcm.Seal(nil, in.IV, in.Data, nil)
	return out, nil
}

func (*AesGcm) Decrypt(key *Key, en *Encoded) ([]byte, error) {
	b, err := aes.NewCipher(key.Key)
	if err != nil {
		return nil, fmt.Errorf("aes NewCipher failed: %w", err)
	}
	gcm, err := cipher.NewGCM(b)
	if err != nil {
		return nil, fmt.Errorf("cipher NewGCM failed: %w", err)
	}
	return gcm.Open(nil, en.IV, en.Data, nil)
}
