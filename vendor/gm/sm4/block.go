package sm4

func rl(x uint32, i uint8) uint32 { return (x << (i % 32)) | (x >> (32 - (i % 32))) }

func l0(b uint32) uint32 { return b ^ rl(b, 13) ^ rl(b, 23) }

func feistel0(x0, x1, x2, x3, rk uint32) uint32 { return x0 ^ l0(p(x1^x2^x3^rk)) }

//非线性变换τ(.)
func p(a uint32) uint32 {
	return (uint32(sbox[a>>24]) << 24) ^ (uint32(sbox[(a>>16)&0xff]) << 16) ^ (uint32(sbox[(a>>8)&0xff]) << 8) ^ uint32(sbox[(a)&0xff])
}

func permuteInitialBlock(b []uint32, block []byte) {
	for i := 0; i < 4; i++ {
		b[i] = (uint32(block[i*4]) << 24) | (uint32(block[i*4+1]) << 16) |
			(uint32(block[i*4+2]) << 8) | (uint32(block[i*4+3]))
	}
}

func permuteFinalBlock(b []byte, block []uint32) {
	for i := 0; i < 4; i++ {
		b[i*4] = uint8(block[i] >> 24)
		b[i*4+1] = uint8(block[i] >> 16)
		b[i*4+2] = uint8(block[i] >> 8)
		b[i*4+3] = uint8(block[i])
	}
}

// Encrypt one block from src into dst, using the expanded key xk.
func cryptBlock(subkeys []uint32, b []uint32, r []byte, dst, src []byte, decrypt bool) {
	var x uint32
	permuteInitialBlock(b, src)
	if decrypt {
		for i := 0; i < 8; i++ {
			x = b[1] ^ b[2] ^ b[3] ^ subkeys[31-4*i]
			b[0] = b[0] ^ sbox0[x&0xff] ^ sbox1[(x>>8)&0xff] ^ sbox2[(x>>16)&0xff] ^ sbox3[(x>>24)&0xff]
			x = b[0] ^ b[2] ^ b[3] ^ subkeys[31-4*i-1]
			b[1] = b[1] ^ sbox0[x&0xff] ^ sbox1[(x>>8)&0xff] ^ sbox2[(x>>16)&0xff] ^ sbox3[(x>>24)&0xff]
			x = b[0] ^ b[1] ^ b[3] ^ subkeys[31-4*i-2]
			b[2] = b[2] ^ sbox0[x&0xff] ^ sbox1[(x>>8)&0xff] ^ sbox2[(x>>16)&0xff] ^ sbox3[(x>>24)&0xff]
			x = b[1] ^ b[2] ^ b[0] ^ subkeys[31-4*i-3]
			b[3] = b[3] ^ sbox0[x&0xff] ^ sbox1[(x>>8)&0xff] ^ sbox2[(x>>16)&0xff] ^ sbox3[(x>>24)&0xff]
		}
	} else {
		for i := 0; i < 8; i++ {
			x = b[1] ^ b[2] ^ b[3] ^ subkeys[4*i]
			b[0] = b[0] ^ sbox0[x&0xff] ^ sbox1[(x>>8)&0xff] ^ sbox2[(x>>16)&0xff] ^ sbox3[(x>>24)&0xff]
			x = b[0] ^ b[2] ^ b[3] ^ subkeys[4*i+1]
			b[1] = b[1] ^ sbox0[x&0xff] ^ sbox1[(x>>8)&0xff] ^ sbox2[(x>>16)&0xff] ^ sbox3[(x>>24)&0xff]
			x = b[0] ^ b[1] ^ b[3] ^ subkeys[4*i+2]
			b[2] = b[2] ^ sbox0[x&0xff] ^ sbox1[(x>>8)&0xff] ^ sbox2[(x>>16)&0xff] ^ sbox3[(x>>24)&0xff]
			x = b[1] ^ b[2] ^ b[0] ^ subkeys[4*i+3]
			b[3] = b[3] ^ sbox0[x&0xff] ^ sbox1[(x>>8)&0xff] ^ sbox2[(x>>16)&0xff] ^ sbox3[(x>>24)&0xff]
		}
	}
	b[0], b[1], b[2], b[3] = b[3], b[2], b[1], b[0]
	permuteFinalBlock(r, b)
	copy(dst, r)
}

func generateSubKeys(key []byte) []uint32 {
	subkeys := make([]uint32, 32)
	b := make([]uint32, 4)
	permuteInitialBlock(b, key)
	b[0] ^= fk[0]
	b[1] ^= fk[1]
	b[2] ^= fk[2]
	b[3] ^= fk[3]
	for i := 0; i < 32; i++ {
		subkeys[i] = feistel0(b[0], b[1], b[2], b[3], ck[i])
		b[0], b[1], b[2], b[3] = b[1], b[2], b[3], subkeys[i]
	}
	return subkeys
}