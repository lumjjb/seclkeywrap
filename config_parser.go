package seclkeywrap

import (
	"io/ioutil"
	"strings"

	encconfig "github.com/containers/ocicrypt/config"
	"github.com/pkg/errors"
)

const (
	seclPrefix = "secl:"
)

/*
* Recipient protocol will be secl:kbs-url,kbs-uid,kbs-cert-file-path
* Key string will be secl:wls-url,wls-cert-path
**

 */

type encInfo struct {
	kbsUrl  string
	kbsUid  string
	kbsCert []byte
}

type decInfo struct {
	wlsUrl  string
	wlsCert []byte
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
		ec.Parameters["kbs-url"] = append(ec.Parameters["kbs-url"], []byte(ei.kbsUrl))
		ec.Parameters["kbs-uid"] = append(ec.Parameters["kbs-uid"], []byte(ei.kbsUid))
		ec.Parameters["kbs-cert"] = append(ec.Parameters["kbs-kbs-cert"], ei.kbsCert)
	}

	// Parse keys
	decInfos, err := parseKeys(keys)
	if err != nil {
		return encconfig.CryptoConfig{}, errors.Wrapf(err, "Unable to parse keys")
	}

	dc := encconfig.DecryptConfig{
		Parameters: map[string][][]byte{},
	}

	for _, di := range decInfos {
		dc.Parameters["wls-url"] = append(dc.Parameters["wls-url"], []byte(di.wlsUrl))
		dc.Parameters["wls-cert"] = append(dc.Parameters["wls-kbs-cert"], di.wlsCert)
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
		vars := strings.Split(r, ",")

		if len(vars) != 3 {
			return nil, errors.Errorf("Invalid format of recipient (expecting 3 fields): %v", varString)
		}

		// Format is: kbs-url,kbs-uid,kbs-cert-file-path
		var (
			kbsUrl      string = vars[0]
			kbsUid      string = vars[1]
			kbsCertPath string = vars[2]
		)

		kbsCert, err := ioutil.ReadFile(kbsCertPath)
		if err != nil {
			return nil, errors.Wrapf(err, "Unable to read certfile: %v", kbsCertPath)
		}

		ret = append(ret, encInfo{
			kbsUrl:  kbsUrl,
			kbsUid:  kbsUid,
			kbsCert: kbsCert,
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

		varString := strings.TrimPrefix(k, seclPrefix)
		vars := strings.Split(k, ",")

		if len(vars) != 2 {
			return nil, errors.Errorf("Unablae to parse key: %v", varString)
		}

		// Format is: wls-url,wls-cert-path
		var (
			wlsUrl      string = vars[0]
			wlsCertPath string = vars[1]
		)

		wlsCert, err := ioutil.ReadFile(wlsCertPath)
		if err != nil {
			return nil, errors.Wrapf(err, "Unable to read certfile: %v", wlsCertPath)
		}

		ret = append(ret, decInfo{
			wlsUrl:  wlsUrl,
			wlsCert: wlsCert,
		})
	}

	return ret, nil
}

/*
        EncryptConfig
	var (
		kbsUrl  string = string(ec.Parameters["kbs-url"][0])
		kbsUid  string = string(ec.Parameters["kbs-uid"][0])
		kbsCert []byte = ec.Parameters["kbs-cert"][0]
	)


        DecryptConfig
	var (
		wlsUrl         string = string(dc.Parameters["wls-url"][0])
		wlsCertificate []byte = dc.Parameters["wls-cert"][0]
	)
*/
