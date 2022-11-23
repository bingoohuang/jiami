package main

import (
	"bytes"
	"encoding/base64"
	"io"
	"log"
	"os"
	"strings"

	"github.com/bingoohuang/jiami"
	"github.com/spf13/pflag"
	"github.com/vmihailenco/msgpack/v5"
)

func main() {
	input := pflag.StringP("input", "i", "", "input string")
	passphrase := pflag.StringP("passphrase", "p", "", "passphrase")
	pflag.Parse()

	d, err := DecodeString(*input)
	if err != nil {
		log.Fatalf("base64.StdEncoding.DecodeString failed: %v", err)
	}

	encoded := &jiami.Encoded{}
	if err := msgpack.Unmarshal(d, encoded); err != nil {
		log.Fatalf("msgpack.Unmarshal failed: %v", err)
	}

	if *passphrase == "" {
		*passphrase = os.Getenv("PASSPHRASE")
	}

	key := &jiami.Key{Passphrase: []byte(*passphrase), Salt: encoded.Salt}
	if err := key.Init(); err != nil {
		log.Fatalf("key.Init failed: %v", err)
	}

	plain, err := jiami.NewAesGcm().Decrypt(key, encoded)
	if err != nil {
		log.Fatalf("Decrypt failed: %v", err)
	}

	log.Printf("Plain: %s", plain)
}

// DecodeString decode string which is in base64 format ( any one of StdEncoding/URLEncoding/RawStdEncoding/RawURLEncoding).
func DecodeString(src string) ([]byte, error) {
	var b bytes.Buffer
	if _, err := Decode(&b, strings.NewReader(src)); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// Decode copies io.Reader which is in base64 format ( any one of StdEncoding/URLEncoding/RawStdEncoding/RawURLEncoding).
func Decode(dst io.Writer, src io.Reader) (int64, error) {
	return io.Copy(dst, base64.NewDecoder(base64.RawStdEncoding, &rawStdEncodingReader{Reader: src}))
}

type rawStdEncodingReader struct{ io.Reader }

// StdEncoding：RFC 4648 定义的标准 BASE64 编码字符集，结果填充=，使字节数为4的倍数
// URLEncoding：RFC 4648 定义的另一 BASE64 编码字符集，用 - 和 _ 替换了 + 和 /，用于URL和文件名，结果填充=
// RawStdEncoding：同 StdEncoding，但结果不填充=
// RawURLEncoding：同 URLEncoding，但结果不填充=
func (f *rawStdEncodingReader) Read(p []byte) (int, error) {
	n, err := f.Reader.Read(p)
	for i := 0; i < n; i++ {
		switch p[i] {
		case '-':
			p[i] = '+'
		case '_':
			p[i] = '/'
		case '=':
			n = i
			return n, err
		}
	}

	return n, err
}
