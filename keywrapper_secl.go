package seclkeywrap

import (
	"crypto/ecdsa"
	"encoding/json"

	"github.com/containers/ocicrypt/config"
	"github.com/containers/ocicrypt/keywrap"
	encutils "github.com/containers/ocicrypt/utils"
	"github.com/pkg/errors"
	jose "gopkg.in/square/go-jose.v2"
)

type seclKeyWrapper struct{}
type annotationPacket struct {
	KeyUrl     string `json:"key_url"`
	WrappedKey []byte `json:"wrapped_key"`
}

func NewKeyWrapper() keywrap.KeyWrapper {
	return &seclKeyWrapper{}
}

func (kw *seclKeyWrapper) WrapKeys(ec *config.EncryptConfig, optsData []byte) ([]byte, error) {
	// If no KBS url provided, nothing to encrypt for
	if len(ec.Parameters["kbs-url"]) == 0 {
		return nil, nil
	}

	// Check for required input parameters
	if len(ec.Parameters["kbs-url"]) != 1 || len(ec.Parameters["kbs-uid"]) != 1 || len(ec.Parameters["kbs-cert"]) != 1 {
		return nil, errors.New("Only one KBS parameter is supported")
	}

	var (
		pubKeyBytes []byte
		err         error

		keyUrl  string = ""
		kbsUrl  string = string(ec.Parameters["kbs-url"][0])
		kbsUid  string = string(ec.Parameters["kbs-uid"][0])
		kbsCert []byte = ec.Parameters["kbs-cert"][0]
	)

	// Cache keyUrl in ec.Parameters["kbs-keyurl-cache"] for same process memory encryption
	if len(ec.Parameters["kbs-keyurl-cache"]) == 1 {
		keyUrl = string(ec.Parameters["kbs-keyurl-cache"][0])
	}

	pubKeyBytes, keyUrl, err = getPublicKeyFromBroker(kbsUrl, kbsCert, kbsUid, keyUrl)
	if err != nil {
		return nil, errors.Wrapf(err, "Unable to obtain public key from broker at %v, for keyUrl %v", kbsUrl, keyUrl)
	}

	ec.Parameters["kbs-keyurl-cache"] = [][]byte{[]byte(keyUrl)}

	// Create wrapped key blob
	wrappedKey, err := jweEncrypt(pubKeyBytes, optsData)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to encrypt JWE packet")
	}

	// Create annotation packet
	ap := annotationPacket{
		KeyUrl:     keyUrl,
		WrappedKey: wrappedKey,
	}

	return json.Marshal(ap)
}

func (kw *seclKeyWrapper) UnwrapKey(dc *config.DecryptConfig, annotation []byte) ([]byte, error) {
	// If no WLS url given, nothing to decrypt
	if len(dc.Parameters["wls-url"]) == 0 {
		return nil, nil
	}

	// Check parameters
	if len(dc.Parameters["wls-url"]) != 1 || len(dc.Parameters["wls-cert"]) != 1 {
		return nil, errors.New("Only one WLS parameter is supported")
	}

	var (
		wlsUrl         string = string(dc.Parameters["wls-url"][0])
		wlsCertificate []byte = dc.Parameters["wls-cert"][0]
	)

	var ap annotationPacket
	err := json.Unmarshal(annotation, &ap)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to unmarshal annotation packet")
	}

	// Get private key from server and decrypt packet
	privateKeyBytes, err := getPrivateKeyFromBroker(wlsUrl, wlsCertificate, ap.KeyUrl)
	if err != nil {
		return nil, errors.Wrapf(err, "Unable to obtain key (url: %v) from WLS $v", ap.KeyUrl, wlsUrl)
	}

	return jweDecrypt(privateKeyBytes, ap.WrappedKey)
}

func (kw *seclKeyWrapper) GetAnnotationID() string {
	return "org.opencontainers.image.enc.keys.isecl.jwe"
}

// GetPrivateKeys (optional) gets the array of private keys. It is an optional
// as in some key services, a private key may not be exportable (i.e. HSM)
func (kw *seclKeyWrapper) GetPrivateKeys(dcparameters map[string][][]byte) [][]byte {
	return nil
}

func (kw *seclKeyWrapper) NoPossibleKeys(dcparameters map[string][][]byte) bool {
	return len(dcparameters["wls-url"]) == 0
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
func getPrivateKeyFromBroker(wlsUrl string, wlsCertificate []byte, keyUrl string) (privateKey []byte, err error) {
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
func getPublicKeyFromBroker(kbsUrl string, kbsCert []byte, uid string, keyUrl string) (publicKey []byte, retKeyUrl string, err error) {
	publicKey = []byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnYarY9vO4oiCgMqIWNSt
jUdg+1x0NKKxVBLXhkUsY6JiTSUlj8I3NThHIpML2A9T0GNSCXFpWob3ORxd0LlP
rqSNhXl0PrJlJoT4f1ExV44RjzwwIeqvK3d/KktCQlSbvo4111I4TRHMG1ywtz38
NxE2ID/yyoH5rlUZtKY4pOBV+ktP1V3hCfwPJJAyf/xuGgzpijUCjJYVtmsmGshx
bo3JwGKTAXHD7CmCRXv3eqjHVqPVqWjvfj4KuL0TkncjUmYL7LL/fk7Loxdlhs7Q
fbpN2n9Uj9epE6EFPPPWMbwcd/FETKOJGZCgslfARZisEmvG+5HVEuPKV7uG4Qmb
1wIDAQAB
-----END PUBLIC KEY-----`)
	return publicKey, kbsUrl + "/" + "some-key-id-xxx", nil
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
