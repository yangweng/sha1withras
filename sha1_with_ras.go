package sha1withras

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
)

type SHA1withRSA struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

//设置私锁
func (this *SHA1withRSA) setPrivateKey(pkey []byte) error {
	block, _ := pem.Decode(pkey)
	if block == nil {
		return errors.New("private key error.")
	}

	if priv, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		this.privateKey = priv
		return nil
	}

	if priv, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		this.privateKey = priv.(*rsa.PrivateKey)
		return nil
	} else {
		return err
	}
}

//设置公锁
func (this *SHA1withRSA) setPublicKey(pkey []byte) error {
	block, _ := pem.Decode(pkey)
	if block == nil {
		return errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err == nil {
		this.publicKey = pubInterface.(*rsa.PublicKey)
		return nil
	}
	return err
}

//加密
func (this *SHA1withRSA) Encrypt(plaintext []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, this.publicKey, plaintext)
}

//机密
func (this *SHA1withRSA) Decrypt(ciphertext []byte) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, this.privateKey, ciphertext)
}

//生成sign
func (this *SHA1withRSA) Sign(src []byte) (string, error) {
	h := sha1.New()
	h.Write(src)
	hashed := h.Sum(nil)
	s, err := rsa.SignPKCS1v15(rand.Reader, this.privateKey, crypto.SHA1, hashed)
	if err != nil {
		return "", err
	}
	d := base64.StdEncoding.EncodeToString(s)
	return d, nil
}

//验证sign
func (this *SHA1withRSA) Verify(src []byte, sign string) error {
	h := sha1.New()
	h.Write(src)
	hashed := h.Sum(nil)
	dbuf := make([]byte, 0)
	dbuf, err := base64.StdEncoding.DecodeString(sign)
	if err != nil {
		return err
	}
	return rsa.VerifyPKCS1v15(this.publicKey, crypto.SHA1, hashed, dbuf)
}

//生成新的接口
func New(publicKey, privateKey []byte) (*SHA1withRSA, error) {
	c := new(SHA1withRSA)
	if err := c.setPrivateKey(privateKey); err != nil {
		return nil, err
	}
	if err := c.setPublicKey(publicKey); err != nil {
		return nil, err
	}
	return c, nil
}

//生成缺省接口
func NewDefault(publicKey, privateKey string) (*SHA1withRSA, error) {
	return New([]byte(publicKey), []byte(privateKey))
}
