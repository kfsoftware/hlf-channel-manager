package resolvers

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-config/configtx"
	"github.com/hyperledger/fabric-config/configtx/membership"
	"github.com/hyperledger/fabric-config/configtx/orderer"
	"github.com/hyperledger/fabric-config/protolator"
	appconfig "github.com/kfsoftware/hlf-channel-manager/config"
	"github.com/kfsoftware/hlf-channel-manager/gql/models"
	"github.com/kfsoftware/hlf-channel-manager/store/channel"
	"github.com/kfsoftware/hlf-channel-manager/utils"
	"gopkg.in/yaml.v3"
	"time"
)

func (r *mutationResolver) ComputeChannel(ctx context.Context, name string, config models.ChannelConfig) (*models.ComputeChannelResponse, error) {
	var ordererOrgs []configtx.Organization
	for _, ordOrg := range config.Orderer.Organizations {
		signRootCert, err := utils.ParseX509CertificateBase64(ordOrg.Msp.RootCerts[0])
		if err != nil {
			return nil, err
		}
		tlsRootCert, err := utils.ParseX509CertificateBase64(ordOrg.Msp.TLSRootCerts[0])
		if err != nil {
			return nil, err
		}
		genesisOrdererOrg, err := memberToConfigtxOrg(
			ordOrg.MspID,
			tlsRootCert,
			signRootCert,
			ordOrg.OrdererEndpoints,
			[]configtx.Address{},
		)
		if err != nil {
			return nil, err
		}
		ordererOrgs = append(ordererOrgs, genesisOrdererOrg)
	}
	var peerOrgs []configtx.Organization
	for _, peerOrg := range config.Application.Orgs {
		anchorPeers := []configtx.Address{}
		signRootCert, err := utils.ParseX509CertificateBase64(peerOrg.Msp.RootCerts[0])
		if err != nil {
			return nil, err
		}
		tlsRootCert, err := utils.ParseX509CertificateBase64(peerOrg.Msp.TLSRootCerts[0])
		if err != nil {
			return nil, err
		}
		genesisOrdererOrg, err := memberToConfigtxOrg(
			peerOrg.MspID,
			tlsRootCert,
			signRootCert,
			[]string{},
			anchorPeers,
		)
		if err != nil {
			return nil, err
		}
		peerOrgs = append(peerOrgs, genesisOrdererOrg)
	}
	var consenters []orderer.Consenter
	for _, consenter := range config.Orderer.EtcdRaft.Consenters {
		clientTLSCert, err := utils.ParseX509CertificateBase64(consenter.ClientTLSCert)
		if err != nil {
			return nil, err
		}
		serverTLSCert, err := utils.ParseX509CertificateBase64(consenter.ServerTLSCert)
		if err != nil {
			return nil, err
		}
		genesisConsenter := orderer.Consenter{
			Address: orderer.EtcdAddress{
				Host: consenter.Address.Host,
				Port: consenter.Address.Port,
			},
			ClientTLSCert: clientTLSCert,
			ServerTLSCert: serverTLSCert,
		}
		consenters = append(consenters, genesisConsenter)
	}
	channelConfig := configtx.Channel{
		Orderer: configtx.Orderer{
			OrdererType:   "etcdraft",
			Organizations: ordererOrgs,
			EtcdRaft: orderer.EtcdRaft{
				Consenters: consenters,
				Options: orderer.EtcdRaftOptions{
					TickInterval:         "500ms",
					ElectionTick:         10,
					HeartbeatTick:        1,
					MaxInflightBlocks:    5,
					SnapshotIntervalSize: 16 * 1024 * 1024, // 16 MB
				},
			},
			Policies: map[string]configtx.Policy{
				"Readers": {
					Type: "ImplicitMeta",
					Rule: "ANY Readers",
				},
				"Writers": {
					Type: "ImplicitMeta",
					Rule: "ANY Writers",
				},
				"Admins": {
					Type: "ImplicitMeta",
					Rule: "MAJORITY Admins",
				},
				"BlockValidation": {
					Type: "ImplicitMeta",
					Rule: "ANY Writers",
				},
			},
			Capabilities: []string{"V2_0"},
			BatchSize: orderer.BatchSize{
				MaxMessageCount:   100,
				AbsoluteMaxBytes:  1024 * 1024,
				PreferredMaxBytes: 512 * 1024,
			},
			BatchTimeout: 2 * time.Second,
			State:        "STATE_NORMAL",
		},
		Application: configtx.Application{
			Organizations: peerOrgs,
			Capabilities:  []string{"V2_0"},
			Policies: map[string]configtx.Policy{
				"Readers": {
					Type: "ImplicitMeta",
					Rule: "ANY Readers",
				},
				"Writers": {
					Type: "ImplicitMeta",
					Rule: "ANY Writers",
				},
				"Admins": {
					Type: "ImplicitMeta",
					Rule: "MAJORITY Admins",
				},
				"Endorsement": {
					Type: "ImplicitMeta",
					Rule: "MAJORITY Endorsement",
				},
				"LifecycleEndorsement": {
					Type: "ImplicitMeta",
					Rule: "MAJORITY Endorsement",
				},
			},
			ACLs: defaultACLs(),
		},
		Capabilities: []string{"V2_0"},
		Policies: map[string]configtx.Policy{
			"Readers": {
				Type: "ImplicitMeta",
				Rule: "ANY Readers",
			},
			"Writers": {
				Type: "ImplicitMeta",
				Rule: "ANY Writers",
			},
			"Admins": {
				Type: "ImplicitMeta",
				Rule: "MAJORITY Admins",
			},
		},
	}
	channelID := name
	genesisBlock, err := configtx.NewApplicationChannelGenesisBlock(channelConfig, channelID)
	if err != nil {
		return nil, err
	}
	protoBytes, err := proto.Marshal(genesisBlock)
	if err != nil {
		return nil, err
	}
	blockStr := base64.StdEncoding.EncodeToString(protoBytes)
	var buffer bytes.Buffer
	err = protolator.DeepMarshalJSON(&buffer, genesisBlock)
	if err != nil {
		return nil, err
	}
	return &models.ComputeChannelResponse{
		Name:            name,
		ChannelProtoB64: blockStr,
		ChannelJSONB64:  buffer.String(),
	}, nil
}

func (r *mutationResolver) AddOrg(ctx context.Context, input models.OrgDefinition) (*models.Org, error) {
	//TODO implement me
	panic("implement me")
}

func (r *mutationResolver) DeleteOrg(ctx context.Context, name string) (*models.Org, error) {
	//TODO implement me
	panic("implement me")
}

func memberToConfigtxOrg(mspID string, rootTlsCert *x509.Certificate, signTlsCert *x509.Certificate, ordererUrls []string, anchorPeers []configtx.Address) (configtx.Organization, error) {
	genesisOrg := configtx.Organization{
		Name: mspID,
		MSP: configtx.MSP{
			Name:                 mspID,
			RootCerts:            []*x509.Certificate{signTlsCert},
			CryptoConfig:         membership.CryptoConfig{},
			TLSRootCerts:         []*x509.Certificate{rootTlsCert},
			TLSIntermediateCerts: nil,
			NodeOUs: membership.NodeOUs{
				Enable: true,
				ClientOUIdentifier: membership.OUIdentifier{
					Certificate:                  signTlsCert,
					OrganizationalUnitIdentifier: "client",
				},
				PeerOUIdentifier: membership.OUIdentifier{
					Certificate:                  signTlsCert,
					OrganizationalUnitIdentifier: "peer",
				},
				AdminOUIdentifier: membership.OUIdentifier{
					Certificate:                  signTlsCert,
					OrganizationalUnitIdentifier: "admin",
				},
				OrdererOUIdentifier: membership.OUIdentifier{
					Certificate:                  signTlsCert,
					OrganizationalUnitIdentifier: "orderer",
				},
			},
		},
		OrdererEndpoints: ordererUrls,
		Policies: map[string]configtx.Policy{
			"Admins": {
				Type: "Signature",
				Rule: fmt.Sprintf("OR('%s.admin')", mspID),
			},
			"Readers": {
				Type: "Signature",
				Rule: fmt.Sprintf("OR('%s.member')", mspID),
			},
			"Writers": {
				Type: "Signature",
				Rule: fmt.Sprintf("OR('%s.member')", mspID),
			},
			"Endorsement": {
				Type: "Signature",
				Rule: fmt.Sprintf("OR('%s.member')", mspID),
			},
		},
		AnchorPeers: anchorPeers,
	}
	return genesisOrg, nil
}

func defaultACLs() map[string]string {
	return map[string]string{
		"_lifecycle/CheckCommitReadiness": "/Channel/Application/Writers",

		//  ACL policy for _lifecycle's "CommitChaincodeDefinition" function
		"_lifecycle/CommitChaincodeDefinition": "/Channel/Application/Writers",

		//  ACL policy for _lifecycle's "QueryChaincodeDefinition" function
		"_lifecycle/QueryChaincodeDefinition": "/Channel/Application/Writers",

		//  ACL policy for _lifecycle's "QueryChaincodeDefinitions" function
		"_lifecycle/QueryChaincodeDefinitions": "/Channel/Application/Writers",

		// ---Lifecycle System Chaincode (lscc) function to policy mapping for access control---//

		//  ACL policy for lscc's "getid" function
		"lscc/ChaincodeExists": "/Channel/Application/Readers",

		//  ACL policy for lscc's "getdepspec" function
		"lscc/GetDeploymentSpec": "/Channel/Application/Readers",

		//  ACL policy for lscc's "getccdata" function
		"lscc/GetChaincodeData": "/Channel/Application/Readers",

		//  ACL Policy for lscc's "getchaincodes" function
		"lscc/GetInstantiatedChaincodes": "/Channel/Application/Readers",

		// ---Query System Chaincode (qscc) function to policy mapping for access control---//

		//  ACL policy for qscc's "GetChainInfo" function
		"qscc/GetChainInfo": "/Channel/Application/Readers",

		//  ACL policy for qscc's "GetBlockByNumber" function
		"qscc/GetBlockByNumber": "/Channel/Application/Readers",

		//  ACL policy for qscc's  "GetBlockByHash" function
		"qscc/GetBlockByHash": "/Channel/Application/Readers",

		//  ACL policy for qscc's "GetTransactionByID" function
		"qscc/GetTransactionByID": "/Channel/Application/Readers",

		//  ACL policy for qscc's "GetBlockByTxID" function
		"qscc/GetBlockByTxID": "/Channel/Application/Readers",

		// ---Configuration System Chaincode (cscc) function to policy mapping for access control---//

		//  ACL policy for cscc's "GetConfigBlock" function
		"cscc/GetConfigBlock": "/Channel/Application/Readers",

		//  ACL policy for cscc's "GetChannelConfig" function
		"cscc/GetChannelConfig": "/Channel/Application/Readers",

		// ---Miscellaneous peer function to policy mapping for access control---//

		//  ACL policy for invoking chaincodes on peer
		"peer/Propose": "/Channel/Application/Writers",

		//  ACL policy for chaincode to chaincode invocation
		"peer/ChaincodeToChaincode": "/Channel/Application/Writers",

		// ---Events resource to policy mapping for access control// // // ---//

		//  ACL policy for sending block events
		"event/Block": "/Channel/Application/Readers",

		//  ACL policy for sending filtered block events
		"event/FilteredBlock": "/Channel/Application/Readers",
	}
}

func (r *mutationResolver) SyncChannel(ctx context.Context, channelConfigStr string, saveOrderer bool, saveApplication bool) (*models.SyncChannelResponse, error) {
	channelConfig := appconfig.ChannelConfig{}
	err := yaml.Unmarshal([]byte(channelConfigStr), &channelConfig)
	if err != nil {
		return nil, err
	}
	err = channel.SyncChannel(
		ctx,
		channelConfig,
		r.ChannelManagerConfig,
		r.FabricSDK,
		r.ConfigBackend,
		saveOrderer,
		saveApplication,
	)
	if err != nil {
		return nil, err
	}
	return &models.SyncChannelResponse{
		Success:    true,
		OutputJSON: "",
		OutputPb:   "",
	}, nil

}
