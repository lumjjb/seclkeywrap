package seclkeywrap

import (
	"crypto/ecdsa"
	"encoding/json"
	"os/exec"

	// Sym key enc libs
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"

	"github.com/containers/ocicrypt/config"
	"github.com/containers/ocicrypt/keywrap"
	encutils "github.com/containers/ocicrypt/utils"
	"github.com/pkg/errors"
	jose "gopkg.in/square/go-jose.v2"
)

const (
	// WrapTypeAssymetric uses assymmetric keys to perform wrapping with a JWE packet
	WrapTypeAssymmetric string = "asym"
	// WrapTypeSymmetric uses symmetric keys to perform wrapping with AES_GCM
	WrapTypeSymmetric string = "sym"
)

var (
	WrapMode string = WrapTypeSymmetric
)

type seclKeyWrapper struct{}
type annotationPacket struct {
	KeyUrl     string `json:"key_url"`
	WrappedKey []byte `json:"wrapped_key"`
	WrapType   string `json:"wrap_type"`
}

type aesPacket struct {
	Ciphertext []byte `json:"cipher_text"`
	Nonce      []byte `json:"nonce"`
}

func NewKeyWrapper() keywrap.KeyWrapper {
	return &seclKeyWrapper{}
}

func (kw *seclKeyWrapper) WrapKeys(ec *config.EncryptConfig, optsData []byte) ([]byte, error) {
	// If no KBS url provided, nothing to encrypt for
	if len(ec.Parameters["secl-enabled"]) == 0 {
		return nil, nil
	}

	if len(ec.Parameters["secl-asset-tag"]) != 1 {
		return nil, errors.New("Current support encryption for 1 asset tag at a time")
	}

	assetTag := string(ec.Parameters["secl-asset-tag"][0])

	// Check for required input parameters
	var (
		err error

		keyUrl     string = ""
		wrappedKey []byte = []byte{}
	)

	// Cache keyUrl in ec.Parameters["kbs-keyurl-cache"] for same process memory encryption
	if len(ec.Parameters["keyurl-cache"]) == 1 {
		keyUrl = string(ec.Parameters["keyurl-cache"][0])
	}

	switch WrapMode {
	case WrapTypeAssymmetric:
		var pubKeyBytes []byte
		pubKeyBytes, keyUrl, err = getPublicKeyFromBroker(keyUrl, assetTag)
		if err != nil {
			return nil, errors.Wrapf(err, "Unable to obtain public key from broker")
		}

		// Create wrapped key blob
		wrappedKey, err = jweEncrypt(pubKeyBytes, optsData)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to encrypt JWE packet")
		}

	case WrapTypeSymmetric:
		var symKey []byte
		symKey, keyUrl, err = getEncSymKeyFromBroker(keyUrl, assetTag)
		if err != nil {
			return nil, errors.Wrapf(err, "Unable to obtain sym key from broker")
		}

		// Create wrapped key blob
		wrappedKey, err = aesEncrypt(symKey, optsData)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to encrypt aes_gcm packet")
		}
	}

	ec.Parameters["keyurl-cache"] = [][]byte{[]byte(keyUrl)}

	// Create annotation packet
	ap := annotationPacket{
		KeyUrl:     keyUrl,
		WrappedKey: wrappedKey,
		WrapType:   WrapMode,
	}

	return json.Marshal(ap)
}

func (kw *seclKeyWrapper) UnwrapKey(dc *config.DecryptConfig, annotation []byte) ([]byte, error) {
	// If no WLS url given, nothing to decrypt
	if len(dc.Parameters["secl-enabled"]) == 0 {
		return nil, nil
	}

	var ap annotationPacket
	err := json.Unmarshal(annotation, &ap)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to unmarshal annotation packet")
	}

	switch ap.WrapType {
	case WrapTypeAssymmetric:
		// Get private key from server and decrypt packet
		privateKeyBytes, err := getPrivateKeyFromBroker(ap.KeyUrl)
		if err != nil {
			return nil, errors.Wrapf(err, "Unable to obtain key (url: %v)", ap.KeyUrl)
		}

		return jweDecrypt(privateKeyBytes, ap.WrappedKey)
	case WrapTypeSymmetric:

		// Get private key from server and decrypt packet
		symKey, err := getDecSymKeyFromBroker(ap.KeyUrl)
		if err != nil {
			return nil, errors.Wrapf(err, "Unable to obtain key (url: %v)", ap.KeyUrl)
		}

		return aesDecrypt(symKey, ap.WrappedKey)
	}

	// Get private key from server and decrypt packet
	privateKeyBytes, err := getPrivateKeyFromBroker(ap.KeyUrl)
	if err != nil {
		return nil, errors.Wrapf(err, "Unable to obtain key (url: %v)", ap.KeyUrl)
	}

	return jweDecrypt(privateKeyBytes, ap.WrappedKey)
}

func (kw *seclKeyWrapper) GetAnnotationID() string {
	return "org.opencontainers.image.enc.keys.isecl"
}

// GetPrivateKeys (optional) gets the array of private keys. It is an optional
// as in some key services, a private key may not be exportable (i.e. HSM)
func (kw *seclKeyWrapper) GetPrivateKeys(dcparameters map[string][][]byte) [][]byte {
	return nil
}

func (kw *seclKeyWrapper) NoPossibleKeys(dcparameters map[string][][]byte) bool {
	return len(dcparameters["secl-enabled"]) == 0
}

// GetKeyIdsFromPacket (optional) gets a list of key IDs. This is optional as some encryption
// schemes may not have a notion of key IDs
func (kw *seclKeyWrapper) GetKeyIdsFromPacket(packet string) ([]uint64, error) {
	return nil, nil
}

// GetRecipients (optional) gets a list of recipients. It is optional due to the validity of
// recipients in a particular encryptiong scheme
func (kw *seclKeyWrapper) GetRecipients(packet string) ([]string, error) {
	return nil, nil
}

// getPrivateKeyFromBroker will obtain the Wrapped(privatekey) at keyUrl via the
// workload service at wlsUrl, authenticated with wlsCertificate.
//
// It will then communicate with the local TPM to unwrap the private key.
func getPrivateKeyFromBroker(keyUrl string) (privateKey []byte, err error) {
	privateKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAnYarY9vO4oiCgMqIWNStjUdg+1x0NKKxVBLXhkUsY6JiTSUl
j8I3NThHIpML2A9T0GNSCXFpWob3ORxd0LlPrqSNhXl0PrJlJoT4f1ExV44Rjzww
IeqvK3d/KktCQlSbvo4111I4TRHMG1ywtz38NxE2ID/yyoH5rlUZtKY4pOBV+ktP
1V3hCfwPJJAyf/xuGgzpijUCjJYVtmsmGshxbo3JwGKTAXHD7CmCRXv3eqjHVqPV
qWjvfj4KuL0TkncjUmYL7LL/fk7Loxdlhs7QfbpN2n9Uj9epE6EFPPPWMbwcd/FE
TKOJGZCgslfARZisEmvG+5HVEuPKV7uG4Qmb1wIDAQABAoIBAHjyAvmCtM99XCWi
WxlJAY9tdGrJy3b2SwxwAwZWagR9ktgEY1iDF3xHH2bOW9OhwQpIl54kc21MHti8
jNNK1IEUWoxWeggBVGREx76JCkddDuJYpeQEmkXXU82XRuJCr+mYqoIN4Khbt8hy
XEP01Yc6McKFFtahAKD3OetXjDoZx8sWMG5hAVUssA/QTfxt5a6enZl0W/sW95t1
MFQusNh2B2NGvogj/l/NQ9WxQlG611wQjgnaPHM6qlDJEJwlUQ6fskqyyN/AdoyH
eTPtFcFIRgT4VlU5qeR3bJcDsriCqA1Q9En48RUMRgV8ErguXn5dwd7dbze/TLF2
sFMTZWECgYEAyUHOMYYV/UdkgbyRi+S9zmOBTbnZ42FHWwNJXV3yPv0sTW51Kt92
a5KspesKkmjDjbHsE+13KeA7bSpchpk7NZ1eDdYSDNKJSgtn6UfJrB15QUi94W67
pVxB/unRW8eNFUjKHk8SkNcOwTsQUbVbgxELW+JLuDnisiG1z+YOylkCgYEAyF+6
1X4R1HIGJCkj334iO/joM998nyWDUmFrnflf3QkucnlQsrvCG0SzkzqUHOGjZ+fl
PWHUqK5yozIxNUl3cqXGTnDL7jYjbsiWedE8ytd/hMtQwHa20MxqyslzkP4gFn+F
usygiFeFxlgpm2owH0jD4WyIFryKl0lJi1b8ca8CgYB8R2yi3GA71ZhVHTLrpkcn
af7xFnFcnjfIFhF53Ie5KfHvpuQno3KnHx4KH0iZ/KO1nkdgTuWlMFjCIsScQYd0
pkbsWGMxE9m/pad3QONiq5izHc5TpWOuy3fdiFnGSUXv/NEDQmT+mC7+WBDNxCZM
m3veM7H6g5Rf171EMpazkQKBgQCSeMAXvi+Eb9Gjb1tkzUxzMJF1EeKEZ6SmfMZx
VVDJQCPu1FW0QeIzkrX+YuzQa/TKSM7fXvtYTyVHvLIR9OFXMm1S+8tnF7YxDnpJ
FDXvRTZXOVSPTHh5C2TpVfefvtRv/cog8eJLqEcG5X2MuUPyKnvd9jtI+4wH6S/U
psKkywKBgG/puad5nURLWwMGnWXqgs/ZvYP40wZ1ukkiTJf2037clwH41c/OuikM
3gQRxRtYAAuOsugcQRxcTqqxK0wwCd6cJbVOYS2u1YrWlq+rIKsj+Dpfl9QvL5iG
Tsm/LQaJgmcu66cHvJrMNRbusIUiAy+041X08dD+GkDeJoGsJIc+
-----END RSA PRIVATE KEY-----`)
	return privateKey, nil
}

// getPublicKeyFromBroker will connect to a KBS at kbsUrl with certificate
// kbsCert. It will use uid for authentication with AAS.
//
// If keyUrl == "", it will generate a new key pair and return the public
// key and the associated keyUrl = kbsUrl/keyId
// Else, it will obtain the public key of the given keyUrl
func getPublicKeyFromBroker(keyUrl string, assetTag string) (publicKey []byte, retKeyUrl string, err error) {
	publicKey = []byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnYarY9vO4oiCgMqIWNSt
jUdg+1x0NKKxVBLXhkUsY6JiTSUlj8I3NThHIpML2A9T0GNSCXFpWob3ORxd0LlP
rqSNhXl0PrJlJoT4f1ExV44RjzwwIeqvK3d/KktCQlSbvo4111I4TRHMG1ywtz38
NxE2ID/yyoH5rlUZtKY4pOBV+ktP1V3hCfwPJJAyf/xuGgzpijUCjJYVtmsmGshx
bo3JwGKTAXHD7CmCRXv3eqjHVqPVqWjvfj4KuL0TkncjUmYL7LL/fk7Loxdlhs7Q
fbpN2n9Uj9epE6EFPPPWMbwcd/FETKOJGZCgslfARZisEmvG+5HVEuPKV7uG4Qmb
1wIDAQAB
-----END PUBLIC KEY-----`)
	return publicKey, "https://kbs.url/" + "some-key-id-xxx", nil
}

// KeyInfo if the return json struct from the key broker for a valid key
type KeyInfo struct {
	KeyURL string `json:"key_url"`
	Key    []byte `json:"key"`
}

func getDecSymKeyFromBroker(keyUrl string) (symKey []byte, err error) {
	//symKey = []byte("this_is_a_256_bit_AES_key_12345!")
	//return symKey, nil
	//run wpm to fetch a new key
	cmdout, err := exec.Command("wlagent", "fetch-key-url", keyUrl).Output()
	if err != nil {
		return nil, errors.Wrap(err, "Unable to run wlagent")
	}

	var retKey KeyInfo
	err = json.Unmarshal(cmdout[:], &retKey)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to unmarshal Keyinfo")
	}

	return retKey.Key, nil
}

// getEncSymKeyFromBroker will connect to a KBS at kbsUrl with certificate
// kbsCert. It will use uid for authentication with AAS.
//
// If keyUrl == "", it will generate a new key and return the
// key and the associated keyUrl = kbsUrl/keyId
// Else, it will obtain the key of the given keyUrl
func getEncSymKeyFromBroker(keyUrl string, assetTag string) (symKey []byte, retKeyUrl string, err error) {
	/*
	   symKey = []byte("this_is_a_256_bit_AES_key_12345!")
	   return symKey, kbsUrl + "/" + "some-key-id-xxx", nil
	*/
	var (
		cmdout []byte
	)

	if assetTag == "" {
		//run wpm to fetch a new key
		cmdout, err = exec.Command("wpm", "fetch-key").Output()
		if err != nil {
			return nil, "", errors.Wrap(err, "Unable to run wpm")
		}
	} else {
		// TODO(Haidong) to implement call for asset tag
		return nil, "", errors.New("Not Implemented: asset tag implementation for encryption")
	}

	var retKey KeyInfo
	err = json.Unmarshal(cmdout[:], &retKey)
	if err != nil {

		return nil, "", errors.Wrap(err, "Unable to unmarshal Keyinfo")

	}
	return retKey.Key, retKey.KeyURL, nil
}

// JWE Helper Functions
func jweEncrypt(pubKey []byte, data []byte) ([]byte, error) {
	var joseRecipients []jose.Recipient

	err := jweAddPubKeys(&joseRecipients, [][]byte{pubKey})
	if err != nil {
		return nil, err
	}
	// no recipients is not an error...
	if len(joseRecipients) == 0 {
		return nil, nil
	}

	encrypter, err := jose.NewMultiEncrypter(jose.A256GCM, joseRecipients, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "jose.NewMultiEncrypter failed")
	}
	jwe, err := encrypter.Encrypt(data)
	if err != nil {
		return nil, errors.Wrapf(err, "JWE Encrypt failed")
	}

	return []byte(jwe.FullSerialize()), nil
}

func jweAddPubKeys(joseRecipients *[]jose.Recipient, pubKeys [][]byte) error {
	if len(pubKeys) == 0 {
		return nil
	}
	for _, pubKey := range pubKeys {
		key, err := encutils.ParsePublicKey(pubKey, "JWE")
		if err != nil {
			return err
		}

		alg := jose.RSA_OAEP
		switch key.(type) {
		case *ecdsa.PublicKey:
			alg = jose.ECDH_ES_A256KW
		}

		*joseRecipients = append(*joseRecipients, jose.Recipient{
			Algorithm: alg,
			Key:       key,
		})
	}
	return nil
}

func jweDecrypt(privKey []byte, jweString []byte) ([]byte, error) {
	jwe, err := jose.ParseEncrypted(string(jweString))
	if err != nil {
		return nil, errors.New("jose.ParseEncrypted failed")
	}

	key, err := encutils.ParsePrivateKey(privKey, nil, "JWE")
	if err != nil {
		return nil, err
	}
	_, _, plain, err := jwe.DecryptMulti(key)
	if err != nil {
		return nil, err
	}

	return plain, nil
}

// AES_GCM Helper Functions
func aesEncrypt(key []byte, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("Expected 256 bit key")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	aesp := aesPacket{
		Ciphertext: ciphertext,
		Nonce:      nonce,
	}

	return json.Marshal(aesp)
}

func aesDecrypt(key []byte, data []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("Expected 256 bit key")
	}

	var aesp aesPacket
	err := json.Unmarshal(data, &aesp)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to unmarshal aes packet")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesgcm.Open(nil, aesp.Nonce, aesp.Ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// MAIN
/*
func main() {
	// Initialize wrapper
	kw := NewKeyWrapper()
	key := []byte("this-is-wrapped-key-opts")
	fmt.Printf("Wrapping sensitive content: %s\n\n", key)

	// Encryption input
	kbsUrl := "http://kbs.example.com"
	kbsUid := "some-uid"
	kbsCert := []byte("some-cert")
	ec := &config.EncryptConfig{
		Parameters: map[string][][]byte{
			"kbs-url":  [][]byte{[]byte(kbsUrl)},
			"kbs-uid":  [][]byte{[]byte(kbsUid)},
			"kbs-cert": [][]byte{[]byte(kbsCert)},
		},
	}

	annotation, err := kw.WrapKeys(ec, key)
	if err != nil {
		fmt.Printf("Error: %v", err)
		os.Exit(1)
	}

	fmt.Printf("Wrapped key gave annotation: \n\"%v\" : base64(%s)\n\n", kw.GetAnnotationID(), string(annotation))

	// Decryption input
	wlsUrl := "http://wls.example.com"
	wlsCert := []byte("some-cert")
	dc := &config.DecryptConfig{
		Parameters: map[string][][]byte{
			"wls-url":  [][]byte{[]byte(wlsUrl)},
			"wls-cert": [][]byte{wlsCert},
		},
	}

	out, err := kw.UnwrapKey(dc, annotation)
	if err != nil {
		fmt.Printf("Error: %v", err)
		os.Exit(1)
	}

	fmt.Printf("Output from unwrapping: %s\n\n", out)

	if string(out) != string(key) {
		fmt.Println("BAD!!! Keys don't match!")
	} else {
		fmt.Println("Keys match!")
	}
}
*/
