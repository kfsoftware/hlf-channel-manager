package utils

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net"
)

// Copied from x509.go
var (
	OIDExtensionKeyUsage         = []int{2, 5, 29, 15}
	OIDExtensionExtendedKeyUsage = []int{2, 5, 29, 37}
)

// RFC 5280, 4.2.1.12  Extended Key Usage
//
// anyExtendedKeyUsage OBJECT IDENTIFIER ::= { id-ce-extKeyUsage 0 }
//
// id-kp OBJECT IDENTIFIER ::= { id-pkix 3 }
//
// id-kp-serverAuth             OBJECT IDENTIFIER ::= { id-kp 1 }
// id-kp-clientAuth             OBJECT IDENTIFIER ::= { id-kp 2 }
// id-kp-codeSigning            OBJECT IDENTIFIER ::= { id-kp 3 }
// id-kp-emailProtection        OBJECT IDENTIFIER ::= { id-kp 4 }
// id-kp-timeStamping           OBJECT IDENTIFIER ::= { id-kp 8 }
// id-kp-OCSPSigning            OBJECT IDENTIFIER ::= { id-kp 9 }
var (
	oidExtKeyUsageAny                            = asn1.ObjectIdentifier{2, 5, 29, 37, 0}
	oidExtKeyUsageServerAuth                     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidExtKeyUsageClientAuth                     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	oidExtKeyUsageCodeSigning                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
	oidExtKeyUsageEmailProtection                = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}
	oidExtKeyUsageIPSECEndSystem                 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 5}
	oidExtKeyUsageIPSECTunnel                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 6}
	oidExtKeyUsageIPSECUser                      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 7}
	oidExtKeyUsageTimeStamping                   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	oidExtKeyUsageOCSPSigning                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
	oidExtKeyUsageMicrosoftServerGatedCrypto     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 3}
	oidExtKeyUsageNetscapeServerGatedCrypto      = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 4, 1}
	oidExtKeyUsageMicrosoftCommercialCodeSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 22}
	oidExtKeyUsageMicrosoftKernelCodeSigning     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 61, 1, 1}
)

// extKeyUsageOIDs contains the mapping between an ExtKeyUsage and its OID.
var extKeyUsageOIDs = []struct {
	extKeyUsage x509.ExtKeyUsage
	oid         asn1.ObjectIdentifier
}{
	{x509.ExtKeyUsageAny, oidExtKeyUsageAny},
	{x509.ExtKeyUsageServerAuth, oidExtKeyUsageServerAuth},
	{x509.ExtKeyUsageClientAuth, oidExtKeyUsageClientAuth},
	{x509.ExtKeyUsageCodeSigning, oidExtKeyUsageCodeSigning},
	{x509.ExtKeyUsageEmailProtection, oidExtKeyUsageEmailProtection},
	{x509.ExtKeyUsageIPSECEndSystem, oidExtKeyUsageIPSECEndSystem},
	{x509.ExtKeyUsageIPSECTunnel, oidExtKeyUsageIPSECTunnel},
	{x509.ExtKeyUsageIPSECUser, oidExtKeyUsageIPSECUser},
	{x509.ExtKeyUsageTimeStamping, oidExtKeyUsageTimeStamping},
	{x509.ExtKeyUsageOCSPSigning, oidExtKeyUsageOCSPSigning},
	{x509.ExtKeyUsageMicrosoftServerGatedCrypto, oidExtKeyUsageMicrosoftServerGatedCrypto},
	{x509.ExtKeyUsageNetscapeServerGatedCrypto, oidExtKeyUsageNetscapeServerGatedCrypto},
	{x509.ExtKeyUsageMicrosoftCommercialCodeSigning, oidExtKeyUsageMicrosoftCommercialCodeSigning},
	{x509.ExtKeyUsageMicrosoftKernelCodeSigning, oidExtKeyUsageMicrosoftKernelCodeSigning},
}

// OIDFromExtKeyUsage returns the ASN1 Identifier for a x509.ExtKeyUsage
func OIDFromExtKeyUsage(eku x509.ExtKeyUsage) (oid asn1.ObjectIdentifier, ok bool) {
	for _, pair := range extKeyUsageOIDs {
		if eku == pair.extKeyUsage {
			return pair.oid, true
		}
	}
	return
}

func ExtKeyUsageFromOID(oid asn1.ObjectIdentifier) (eku x509.ExtKeyUsage, ok bool) {
	for _, pair := range extKeyUsageOIDs {
		if oid.Equal(pair.oid) {
			return pair.extKeyUsage, true
		}
	}
	return
}

// asn1BitLength returns the bit-length of bitString by considering the
// most-significant bit in a byte to be the "first" bit. This convention
// matches ASN.1, but differs from almost everything else.
func asn1BitLength(bitString []byte) int {
	bitLen := len(bitString) * 8

	for i := range bitString {
		b := bitString[len(bitString)-i-1]

		for bit := uint(0); bit < 8; bit++ {
			if (b>>bit)&1 == 1 {
				return bitLen
			}
			bitLen--
		}
	}

	return 0
}

// Copied from x509.go
func reverseBitsInAByte(in byte) byte {
	b1 := in>>4 | in<<4
	b2 := b1>>2&0x33 | b1<<2&0xcc
	b3 := b2>>1&0x55 | b2<<1&0xaa
	return b3
}

// Adapted from x509.go
func BuildASN1KeyUsageRequest(usage x509.KeyUsage) (pkix.Extension, error) {
	oidExtensionKeyUsage := pkix.Extension{
		Id:       OIDExtensionKeyUsage,
		Critical: true,
	}
	var a [2]byte
	a[0] = reverseBitsInAByte(byte(usage))
	a[1] = reverseBitsInAByte(byte(usage >> 8))

	l := 1
	if a[1] != 0 {
		l = 2
	}

	bitString := a[:l]
	var err error
	oidExtensionKeyUsage.Value, err = asn1.Marshal(asn1.BitString{Bytes: bitString, BitLength: asn1BitLength(bitString)})
	if err != nil {
		return pkix.Extension{}, err
	}

	return oidExtensionKeyUsage, nil
}

func BuildASN1ExtKeyUsageRequest(usage x509.ExtKeyUsage) (pkix.Extension, error) {
	oidExtensionExtKeyUsage := pkix.Extension{
		Id:       OIDExtensionExtendedKeyUsage,
		Critical: true,
	}
	var a [2]byte
	a[0] = reverseBitsInAByte(byte(usage))
	a[1] = reverseBitsInAByte(byte(usage >> 8))

	l := 1
	if a[1] != 0 {
		l = 2
	}

	bitString := a[:l]
	var err error
	oidExtensionExtKeyUsage.Value, err = asn1.Marshal(asn1.BitString{Bytes: bitString, BitLength: asn1BitLength(bitString)})
	if err != nil {
		return pkix.Extension{}, err
	}

	return oidExtensionExtKeyUsage, nil
}

var (
	// OIDSubjectAltName is the OID for subjectAltName
	OIDSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}
	// OIDReceptorName is the OID for a Receptor node ID
	OIDReceptorName = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2312, 19, 1}
	// OIDHLFExtension is the OID for the HLF extensions 1.2.3.4.5.6.7.8.1
	OIDHLFExtension = asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7, 8, 1}
)

// OtherNameEncode is used for encoding the OtherName field of an x.509 subjectAltName
type OtherNameEncode struct {
	OID   asn1.ObjectIdentifier
	Value UTFString `asn1:"tag:0"`
}

// UTFString is used for encoding a UTF-8 string
type UTFString struct {
	A string `asn1:"utf8"`
}

func BuildHLFExtension() (pkix.Extension, error) {
	value := `{"attrs":{"hf.Affiliation":"","hf.EnrollmentID":"admin","hf.Type":"admin"}}`
	sanExt := pkix.Extension{
		Id:       OIDHLFExtension,
		Critical: false,
		Value:    []byte(value),
	}
	return sanExt, nil
}

// MakeReceptorSAN generates a subjectAltName extension, optionally containing Receptor names
func MakeReceptorSAN(DNSNames []string, IPAddresses []net.IP, NodeIDs []string) (pkix.Extension, error) {
	var rawValues []asn1.RawValue
	for _, name := range DNSNames {
		rawValues = append(rawValues, asn1.RawValue{Tag: 2, Class: 2, Bytes: []byte(name)})
	}
	for _, rawIP := range IPAddresses {
		ip := rawIP.To4()
		if ip == nil {
			ip = rawIP
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: 7, Class: 2, Bytes: ip})
	}
	for _, nodeID := range NodeIDs {
		var err error
		var asnOtherName []byte
		asnOtherName, err = asn1.Marshal(OtherNameEncode{
			OID:   OIDReceptorName,
			Value: UTFString{A: nodeID},
		})
		if err != nil {
			return pkix.Extension{}, err
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: 0, Class: 2, IsCompound: true, Bytes: asnOtherName[2:]})
	}
	sanBytes, err := asn1.Marshal(rawValues)
	if err != nil {
		return pkix.Extension{}, err
	}
	sanExt := pkix.Extension{
		Id:       OIDSubjectAltName,
		Critical: false,
		Value:    sanBytes,
	}
	return sanExt, nil
}
