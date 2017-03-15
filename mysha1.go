// SHA
package mysha1

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
)

type MySha struct {
}

func New() *MySha {
	return &MySha{}
}

func rsaSignSha1Base64(privSign *rsa.PrivateKey, data []byte) (string, error) {
	h := sha1.New()
	h.Write([]byte(data))
	digest := h.Sum(nil)

	ciphertext, err := rsa.SignPKCS1v15(nil, privSign, crypto.SHA1, digest)
	if err != nil {
		return "", nil
	}

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

//privKey 为pem秘钥源文件,转成byte格式传入、body为要加密的字符串。
func (ms *MySha) RsaSignSha1AndBase64(privKey []byte, body []byte) (string, error) {

	block, _ := pem.Decode([]byte(privKey))
	rasPK, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}

	return rsaSignSha1Base64(rasPK, []byte(body))
}
