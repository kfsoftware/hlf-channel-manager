package config

import "time"

type HLFChannelManagerConfig struct {
	DCs []DC `yaml:"dcs"`
}
type DC struct {
	Name       string `yaml:"name"`
	KubeConfig string `yaml:"kubeconfig"`
}

type ChannelConfig struct {
	Name             string         `yaml:"name"`
	Consenters       []Consenter    `yaml:"consenters"`
	PeerOrgs         []PeerOrg      `yaml:"peerOrgs"`
	OrdererOrgs      []OrdererOrg   `yaml:"ordererOrgs"`
	PeerAdminOrgs    []AdminOrg     `yaml:"peerAdminOrgs"`
	OrdererAdminOrgs []AdminOrg     `yaml:"ordererAdminOrgs"`
	Params           *ChannelParams `yaml:"params"`
}

type ChannelParams struct {
	Orderer     *OrdererParams     `yaml:"orderer"`
	Application *ApplicationParams `yaml:"application"`
}
type OrdererParams struct {
	Capabilities []string `yaml:"capabilities"`
	// 		BatchSize: orderer.BatchSize{
	//			MaxMessageCount:   100,
	//			AbsoluteMaxBytes:  1024 * 1024,
	//			PreferredMaxBytes: 512 * 1024,
	//		},
	//		BatchTimeout: 2 * time.Second,
	//		State:        "STATE_NORMAL",
	BatchTimeout *time.Duration `yaml:"batchTimeout"`
	//BatchSize time.Duration `yaml:"batchTimeout"`
	ETCDRaft *ETCDRaft `yaml:"etcdRaft"`
}
type ETCDRaft struct {
	Options *ETCDRaftOptions `yaml:"options"`
}
type ETCDRaftOptions struct {
	TickInterval         *string `yaml:"TickInterval"`
	ElectionTick         *uint32 `yaml:"ElectionTick"`
	HeartbeatTick        *uint32 `yaml:"HeartbeatTick"`
	MaxInflightBlocks    *uint32 `yaml:"MaxInflightBlocks"`
	SnapshotIntervalSize *uint32 `yaml:"SnapshotIntervalSize"`
}

type ApplicationParams struct {
	Capabilities []string        `yaml:"capabilities"`
	Policies     *PoliciesParams `yaml:"policies"`
}

type PoliciesParams struct {
	Readers              *Policy `yaml:"Readers"`
	Writers              *Policy `yaml:"Writers"`
	Admins               *Policy `yaml:"Admins"`
	Endorsement          *Policy `yaml:"Endorsement"`
	LifecycleEndorsement *Policy `yaml:"LifecycleEndorsement"`
}

// Policy is an expression used to define rules for access to channels, chaincodes, etc.
type Policy struct {
	Type      string `yaml:"Type"`
	Rule      string `yaml:"Rule"`
	ModPolicy string `yaml:"ModPolicy"`
}
type AdminOrg struct {
	MSPID string `yaml:"mspid"`
	User  string `yaml:"user"`
}

type PeerOrg struct {
	MSPID string `yaml:"mspid"`
	CA    CA     `yaml:"ca"`
}
type OrdererOrg struct {
	MSPID    string    `yaml:"mspid"`
	CA       CA        `yaml:"ca"`
	Orderers []Orderer `yaml:"orderers"`
}
type Orderer struct {
	Name string `yaml:"name"`
	DC   string `yaml:"dc"`
}

type CA struct {
	Name string `yaml:"name"`
	DC   string `yaml:"dc"`
}
type Consenter struct {
	Name string `yaml:"name"`
	DC   string `yaml:"dc"`
}
