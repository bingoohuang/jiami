package jiami

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAES(t *testing.T) {
	plain := Plain{
		Data:           []byte("君住长江头，我住长江尾，日日思君不见君，共饮长江水"),
		Salt:           nil,
		IV:             nil,
		AdditionalData: nil,
	}
	k := &Key{
		Passphrase: []byte("hello"),
	}
	err := k.Init()
	assert.Nil(t, err)

	g := NewAesGcm()
	encoded, err := g.Encrypt(k, &plain)
	assert.Nil(t, err)
	data, err := g.Decrypt(k, encoded)
	assert.Nil(t, err)
	assert.Equal(t, plain.Data, data)
}
