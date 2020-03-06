package seclkeywrap

import (
	"strings"

	encconfig "github.com/containers/ocicrypt/config"
	"github.com/pkg/errors"
)

const (
	seclPrefix = "secl:"
)

/*
* Recipient protocol will be secl:any for just trusted, or secl:<asset tag>
* for use of asset tag
* Key string will be secl:enabled
 */

type encInfo struct {
	// assetTag indicates which asset tag to use, "" indicates none
	// and should be runnable by any trusted node
	assetTag string
}

type decInfo struct {
	// seclEnabled indicates if secl is enabled
	seclEnabled bool
}

// CreateCryptoConfig
func CreateCryptoConfig(recipients []string, keys []string) (encconfig.CryptoConfig, error) {
	// Parse recipients
	encInfos, err := parseRecipients(recipients)
	if err != nil {
		return encconfig.CryptoConfig{}, errors.Wrapf(err, "Unable to parse recipients")
	}

	ec := encconfig.EncryptConfig{
		Parameters: map[string][][]byte{},
	}
	for _, ei := range encInfos {
		ec.Parameters["secl-enabled"] = append(ec.Parameters["secl-enabled"], []byte("yes"))
		ec.Parameters["secl-asset-tag"] = append(ec.Parameters["secl-asset-tag"], []byte(ei.assetTag))
	}

	// Parse keys
	decInfos, err := parseKeys(keys)
	if err != nil {
		return encconfig.CryptoConfig{}, errors.Wrapf(err, "Unable to parse keys")
	}

	dc := encconfig.DecryptConfig{
		Parameters: map[string][][]byte{},
	}

	for range decInfos {
		dc.Parameters["secl-enabled"] = append(dc.Parameters["secl-enabled"], []byte("yes"))
	}

	ec.DecryptConfig = dc

	cc := encconfig.CryptoConfig{
		EncryptConfig: &ec,
		DecryptConfig: &dc,
	}

	return cc, nil
}

// FilterRecipients takes out any recipient entries for this protocol
func FilterRecipients(recipients []string) []string {
	return filterPrefix(recipients)
}

// FilterKeys takes out any key entries for this protocol
func FilterKeys(keys []string) []string {
	return filterPrefix(keys)
}

func filterPrefix(ss []string) []string {
	ret := []string{}
	for _, s := range ss {
		if !strings.HasPrefix(s, seclPrefix) {
			ret = append(ret, s)
		}
	}

	return ret
}

func parseRecipients(recipients []string) ([]encInfo, error) {
	ret := []encInfo{}
	for _, r := range recipients {
		if !strings.HasPrefix(r, seclPrefix) {
			continue
		}

		varString := strings.TrimPrefix(r, seclPrefix)
		assetTag := ""
		if varString != "any" {
			assetTag = varString
		}

		ret = append(ret, encInfo{
			assetTag: assetTag,
		})
	}

	return ret, nil
}

func parseKeys(keys []string) ([]decInfo, error) {
	ret := []decInfo{}
	for _, k := range keys {
		if !strings.HasPrefix(k, seclPrefix) {
			continue
		}

		ret = append(ret, decInfo{})
	}

	return ret, nil
}
