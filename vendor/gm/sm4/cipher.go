package sm4

import (
	"crypto/cipher"
	"strconv"
)

// The AES block size in bytes.
const BlockSize = 16

// A cipher is an instance of AES encryption using a particular key.
type sm4Cipher struct {
	subkeys []uint32
	block1  []uint32
	block2  []byte
}

type KeySizeError int

func (k KeySizeError) Error() string {
	return "gm/sm4: invalid key size " + strconv.Itoa(int(k))
}

// NewCipher creates and returns a new cipher.Block.
func NewCipher(key []byte) (cipher.Block, error) {
	if len(key) != BlockSize {
		return nil, KeySizeError(len(key))
	}
	c := new(sm4Cipher)
	c.subkeys = generateSubKeys(key)
	c.block1 = make([]uint32, 4)
	c.block2 = make([]byte, 16)
	return c, nil
}

func (c *sm4Cipher) BlockSize() int { return BlockSize }

func (c *sm4Cipher) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("gm/sm4: input not full block")
	}
	if len(dst) < BlockSize {
		panic("gm/sm4: output not full block")
	}
	cryptBlock(c.subkeys, c.block1, c.block2, dst, src, false)
}

func (c *sm4Cipher) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("gm/sm4: input not full block")
	}
	if len(dst) < BlockSize {
		panic("gm/sm4: output not full block")
	}
	cryptBlock(c.subkeys, c.block1, c.block2, dst, src, true)
}