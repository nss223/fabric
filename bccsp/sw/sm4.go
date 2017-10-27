package sw

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/gm/sm4"
)

func GetRandomBytessm4(len int) ([]byte, error) {
	if len < 0 {
		return nil, errors.New("Len must be larger than 0")
	}

	buffer := make([]byte, len)

	n, err := rand.Read(buffer)
	if err != nil {
		return nil, err
	}
	if n != len {
		return nil, fmt.Errorf("Buffer not filled. Requested [%d], got [%d]", len, n)
	}

	return buffer, nil
}

func sm4pkcs7Padding(src []byte) []byte {
	padding := sm4.BlockSize - len(src)%sm4.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func sm4pkcs7UnPadding(src []byte) ([]byte, error) {
	length := len(src)
	unpadding := int(src[length-1])

	if unpadding > sm4.BlockSize || unpadding == 0 {
		return nil, errors.New("Invalid pkcs7 padding (unpadding > sm4.BlockSize || unpadding == 0)")
	}

	pad := src[len(src)-unpadding:]
	for i := 0; i < unpadding; i++ {
		if pad[i] != byte(unpadding) {
			return nil, errors.New("Invalid pkcs7 padding (pad[i] != unpadding)")
		}
	}

	return src[:(length - unpadding)], nil
}

func sm4CBCEncrypt(key, s []byte) ([]byte, error) {
	if len(s)%sm4.BlockSize != 0 {
		return nil, errors.New("Invalid plaintext. It must be a multiple of the block size")
	}

	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, sm4.BlockSize+len(s))
	iv := ciphertext[:sm4.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[sm4.BlockSize:], s)

	return ciphertext, nil
}

func sm4CBCDecrypt(key, src []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(src) < sm4.BlockSize {
		return nil, errors.New("Invalid ciphertext. It must be a multiple of the block size")
	}
	iv := src[:sm4.BlockSize]
	src = src[sm4.BlockSize:]

	if len(src)%sm4.BlockSize != 0 {
		return nil, errors.New("Invalid ciphertext. It must be a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	mode.CryptBlocks(src, src)

	return src, nil
}

// SM4CBCPKCS7Encrypt combines CBC encryption and PKCS7 padding
func SM4CBCPKCS7Encrypt(key, src []byte) ([]byte, error) {
	// First pad
	tmp := sm4pkcs7Padding(src)

	// Then encrypt
	return sm4CBCEncrypt(key, tmp)
}

// SM4CBCPKCS7Decrypt combines CBC decryption and PKCS7 unpadding
func SM4CBCPKCS7Decrypt(key, src []byte) ([]byte, error) {
	// First decrypt
	pt, err := sm4CBCDecrypt(key, src)
	if err == nil {
		return sm4pkcs7UnPadding(pt)
	}
	return nil, err
}

type sm4cbcpkcs7Encryptor struct{}

func (*sm4cbcpkcs7Encryptor) Encrypt(k bccsp.Key, plaintext []byte, opts bccsp.EncrypterOpts) (ciphertext []byte, err error) {
	switch opts.(type) {
	case *bccsp.SM4CBCPKCS7ModeOpts, bccsp.SM4CBCPKCS7ModeOpts:
		// SM4 in CBC mode with PKCS7 padding
		return SM4CBCPKCS7Encrypt(k.(*sm4PrivateKey).privKey, plaintext)
	default:
		return nil, fmt.Errorf("Mode not recognized [%s]", opts)
	}
}

type sm4cbcpkcs7Decryptor struct{}

func (*sm4cbcpkcs7Decryptor) Decrypt(k bccsp.Key, ciphertext []byte, opts bccsp.DecrypterOpts) (plaintext []byte, err error) {
	// check for mode
	switch opts.(type) {
	case *bccsp.SM4CBCPKCS7ModeOpts, bccsp.SM4CBCPKCS7ModeOpts:
		// SM4 in CBC mode with PKCS7 padding
		return SM4CBCPKCS7Decrypt(k.(*sm4PrivateKey).privKey, ciphertext)
	default:
		return nil, fmt.Errorf("Mode not recognized [%s]", opts)
	}
}