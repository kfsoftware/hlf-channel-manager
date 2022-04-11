package utils

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
)

func ParseX509Certificate(contents []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(contents)
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return crt, nil
}

func EncodeX509CertificatesToPem(crts []*x509.Certificate) []string {
	var pems []string
	for _, crt := range crts {
		pems = append(pems, string(EncodeX509Certificate(crt)))
	}

	return pems
}
func ParseX509CertificateBase64(b64Cert string) (*x509.Certificate, error) {
	certBytes, err := base64.StdEncoding.DecodeString(b64Cert)
	if err != nil {
		return nil, err
	}
	crt, err := ParseX509Certificate(certBytes)
	if err != nil {
		return nil, err
	}
	return crt, nil
}

func EncodeX509Certificate(crt *x509.Certificate) []byte {
	pemPk := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: crt.Raw,
	})
	return pemPk
}
