package bccsp

const {
	//国密分组密码算法SM4
	SM4 = "SM4"
}

type SM4KeyGenOpts struct {
	Temporary bool
}

func (opts *SM4KeyGenOpts) Algorithm() string {
	return SM4
}

func (opts *SM4KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

// SM4CBCPKCS7ModeOpts contains options for SM4 encryption in CBC mode
// with PKCS7 padding.
type SM4CBCPKCS7ModeOpts struct{}

// HMACTruncated256SM4DeriveKeyOpts contains options for HMAC truncated
// at 256 bits key derivation.
type HMACTruncated256SM4DeriveKeyOpts struct {
	Temporary bool
	Arg       []byte
}

// Algorithm returns the key derivation algorithm identifier (to be used).
func (opts *HMACTruncated256SM4DeriveKeyOpts) Algorithm() string {
	return HMACTruncated256
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *HMACTruncated256SM4DeriveKeyOpts) Ephemeral() bool {
	return opts.Temporary
}

// Argument returns the argument to be passed to the HMAC
func (opts *HMACTruncated256SM4DeriveKeyOpts) Argument() []byte {
	return opts.Arg
}
// SM4ImportKeyOpts contains options for importing SM4 keys.
type SM4ImportKeyOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *SM4ImportKeyOpts) Algorithm() string {
	return SM4
}

// Ephemeral returns true if the key generated has to be ephemeral,
// false otherwise.
func (opts *SM4ImportKeyOpts) Ephemeral() bool {
	return opts.Temporary
}