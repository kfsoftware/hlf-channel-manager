package org

type Org struct {
	MSPID             string
	SignCACertificate string
	TLSCACertificate  string
}
type Store interface {
	AddOrg(org *Org) error
	GetOrg(mspID string) (*Org, error)
	DeleteOrg(mspID string) error
	GetAllOrgs() ([]*Org, error)
}
