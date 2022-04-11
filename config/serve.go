package config

type GatewayParams struct {
	PeerUrl       string
	PeerTLSCACert []byte
	MSPID         string
}

var ContractCtxKey = &contextKey{"contract"}
var GatewayCtxKey = &contextKey{"gateway"}

type contextKey struct {
	name string
}
