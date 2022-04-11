package channel

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-config/configtx"
	"github.com/hyperledger/fabric-config/configtx/membership"
	"github.com/hyperledger/fabric-config/configtx/orderer"
	cb "github.com/hyperledger/fabric-protos-go/common"
	mspclient "github.com/hyperledger/fabric-sdk-go/pkg/client/msp"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/resmgmt"
	context2 "github.com/hyperledger/fabric-sdk-go/pkg/common/providers/context"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/msp"
	"github.com/hyperledger/fabric-sdk-go/pkg/fab/resource"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	msp2 "github.com/hyperledger/fabric-sdk-go/pkg/msp"
	"github.com/hyperledger/fabric/protoutil"
	appconfig "github.com/kfsoftware/hlf-channel-manager/config"
	"github.com/kfsoftware/hlf-channel-manager/log"
	"github.com/kfsoftware/hlf-channel-manager/utils"
	operatorv1 "github.com/kfsoftware/hlf-operator/pkg/client/clientset/versioned"
	"github.com/lithammer/shortuuid/v3"
	"github.com/pkg/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"strings"
	"time"
)

func getResmgmtClient(sdk *fabsdk.FabricSDK, adminOrg appconfig.AdminOrg, configBackends []core.ConfigBackend) (*resmgmt.Client, context2.ClientProvider, msp.SigningIdentity, error) {
	identityCtx, err := msp2.ConfigFromBackend(configBackends...)
	if err != nil {
		return nil, nil, nil, err
	}
	caConfig, ok := identityCtx.CAConfig(adminOrg.CA)
	if !ok {
		return nil, nil, nil, fmt.Errorf("CA not found: %s", adminOrg.CA)
	}
	sdkContext := sdk.Context(
		fabsdk.WithOrg(adminOrg.MSPID),
	)
	mspClient, err := mspclient.New(
		sdkContext,
		mspclient.WithCAInstance(adminOrg.CA),
		mspclient.WithOrg(adminOrg.MSPID),
	)
	if err != nil {
		return nil, nil, nil, err
	}
	err = mspClient.Enroll(caConfig.Registrar.EnrollID, mspclient.WithSecret(caConfig.Registrar.EnrollSecret))
	if err != nil {
		return nil, nil, nil, err
	}
	adminName := shortuuid.New()[6:]
	secret := "adminpw"
	_, err = mspClient.Register(&mspclient.RegistrationRequest{
		Name:           adminName,
		Type:           "admin",
		MaxEnrollments: -1,
		Affiliation:    "",
		Attributes:     nil,
		CAName:         "ca",
		Secret:         secret,
	})
	if err != nil {
		return nil, nil, nil, err
	}
	err = mspClient.Enroll(adminName, mspclient.WithSecret(secret))
	if err != nil {
		return nil, nil, nil, err
	}
	adminUser, err := mspClient.GetSigningIdentity(adminName)
	if err != nil {
		return nil, nil, nil, err
	}
	sdkContext = sdk.Context(
		fabsdk.WithIdentity(adminUser),
		fabsdk.WithOrg(adminOrg.MSPID),
	)
	resClient, err := resmgmt.New(sdkContext)
	if err != nil {
		return nil, nil, nil, err
	}
	return resClient, sdkContext, adminUser, nil
}

func SyncChannel(
	ctx context.Context,
	channelConfig appconfig.ChannelConfig,
	channelManagerConfig appconfig.HLFChannelManagerConfig,
	sdk *fabsdk.FabricSDK,
	configBackends []core.ConfigBackend,
	saveOrderer bool,
	savePeer bool,
) error {
	firstAdminOrg := channelConfig.PeerAdminOrgs[0]
	resClient, _, _, err := getResmgmtClient(sdk, firstAdminOrg, configBackends)
	if err != nil {
		return err
	}
	channelExists := true
	channelBlock, err := resClient.QueryConfigBlockFromOrderer(channelConfig.Name)
	if err != nil {
		log.Infof("channel %s does not exist, it will be created", channelConfig.Name)
		channelExists = false
	}
	dcs := map[string]*operatorv1.Clientset{}
	for _, dc := range channelManagerConfig.DCs {
		var config *rest.Config

		config, err = clientcmd.BuildConfigFromFlags("", dc.KubeConfig)
		if err != nil {
			log.Errorf("failed to build config from %v", err)
			return err
		}
		hlfClient, err := operatorv1.NewForConfig(config)
		if err != nil {
			log.Errorf("failed to build hlf client from %v", err)
			return err
		}
		dcs[dc.Name] = hlfClient
	}
	var ordererOrgs []configtx.Organization
	for _, ordOrg := range channelConfig.OrdererOrgs {
		hlfClient := dcs[ordOrg.CA.DC]
		ca, err := hlfClient.HlfV1alpha1().FabricCAs("default").Get(ctx, ordOrg.CA.Name, v1.GetOptions{})
		if err != nil {
			log.Errorf("failed to get ca %v", err)
			return err
		}
		signRootCert, err := utils.ParseX509Certificate([]byte(ca.Status.CACert))
		if err != nil {
			return err
		}
		tlsRootCert, err := utils.ParseX509Certificate([]byte(ca.Status.TLSCACert))
		if err != nil {
			return err
		}
		var ordererUrls []string
		for _, ordererItem := range ordOrg.Orderers {
			ord, err := hlfClient.HlfV1alpha1().FabricOrdererNodes("default").Get(ctx, ordererItem.Name, v1.GetOptions{})
			if err != nil {
				log.Errorf("failed to get ord %v", err)
				return err
			}
			istioPort := ord.Spec.Istio.Port
			istioHost := ord.Spec.Istio.Hosts[0]
			ordererUrls = append(ordererUrls, fmt.Sprintf("%s:%d", istioHost, istioPort))
		}
		genesisOrdererOrg, err := memberToConfigtxOrg(
			ordOrg.MSPID,
			tlsRootCert,
			signRootCert,
			ordererUrls,
			[]configtx.Address{},
		)
		if err != nil {
			return err
		}
		ordererOrgs = append(ordererOrgs, genesisOrdererOrg)
	}
	var peerOrgs []configtx.Organization
	for _, peerOrg := range channelConfig.PeerOrgs {
		anchorPeers := []configtx.Address{}
		hlfClient := dcs[peerOrg.CA.DC]
		ca, err := hlfClient.HlfV1alpha1().FabricCAs("default").Get(ctx, peerOrg.CA.Name, v1.GetOptions{})
		if err != nil {
			log.Errorf("failed to get ca %v", err)
			return err
		}
		signRootCert, err := utils.ParseX509Certificate([]byte(ca.Status.CACert))
		if err != nil {
			return err
		}
		tlsRootCert, err := utils.ParseX509Certificate([]byte(ca.Status.TLSCACert))
		if err != nil {
			return err
		}
		genesisPeerOrg, err := memberToConfigtxOrg(
			peerOrg.MSPID,
			tlsRootCert,
			signRootCert,
			[]string{},
			anchorPeers,
		)
		if err != nil {
			return err
		}
		peerOrgs = append(peerOrgs, genesisPeerOrg)
	}
	var consenters []orderer.Consenter
	for _, consenter := range channelConfig.Consenters {
		hlfClient := dcs[consenter.DC]
		ord, err := hlfClient.HlfV1alpha1().FabricOrdererNodes("default").Get(ctx, consenter.Name, v1.GetOptions{})
		if err != nil {
			log.Errorf("failed to get ord %v", err)
			return err
		}
		tlsCert, err := utils.ParseX509Certificate([]byte(ord.Status.TlsCert))
		if err != nil {
			return err
		}
		istioPort := ord.Spec.Istio.Port
		istioHost := ord.Spec.Istio.Hosts[0]
		genesisConsenter := orderer.Consenter{
			Address: orderer.EtcdAddress{
				Host: istioHost,
				Port: istioPort,
			},
			ClientTLSCert: tlsCert,
			ServerTLSCert: tlsCert,
		}
		consenters = append(consenters, genesisConsenter)
	}
	application := configtx.Application{
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
	}
	if channelConfig.Params != nil {
		if channelConfig.Params.Application != nil {
			if len(channelConfig.Params.Application.Capabilities) > 0 {
				application.Capabilities = channelConfig.Params.Application.Capabilities
			}
			if channelConfig.Params.Application.Policies != nil {
				if channelConfig.Params.Application.Policies.Readers != nil {
					application.Policies["Readers"] = mapPolicy(*channelConfig.Params.Application.Policies.Readers)
				}
				if channelConfig.Params.Application.Policies.Writers != nil {
					application.Policies["Writers"] = mapPolicy(*channelConfig.Params.Application.Policies.Writers)
				}
				if channelConfig.Params.Application.Policies.Admins != nil {
					application.Policies["Admins"] = mapPolicy(*channelConfig.Params.Application.Policies.Admins)
				}
				if channelConfig.Params.Application.Policies.Endorsement != nil {
					application.Policies["Endorsement"] = mapPolicy(*channelConfig.Params.Application.Policies.Endorsement)
				}
				if channelConfig.Params.Application.Policies.LifecycleEndorsement != nil {
					application.Policies["LifecycleEndorsement"] = mapPolicy(*channelConfig.Params.Application.Policies.LifecycleEndorsement)
				}
			}
		}
	}
	ordConfigtx := configtx.Orderer{
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
	}
	if channelConfig.Params.Orderer != nil {
		if channelConfig.Params.Orderer.BatchTimeout != nil {
			ordConfigtx.BatchTimeout = *channelConfig.Params.Orderer.BatchTimeout
		}
		if channelConfig.Params.Orderer.ETCDRaft != nil {
			if channelConfig.Params.Orderer.ETCDRaft.Options != nil {
				if channelConfig.Params.Orderer.ETCDRaft.Options.TickInterval != nil {
					ordConfigtx.EtcdRaft.Options.TickInterval = *channelConfig.Params.Orderer.ETCDRaft.Options.TickInterval
				}
				if channelConfig.Params.Orderer.ETCDRaft.Options.ElectionTick != nil {
					ordConfigtx.EtcdRaft.Options.ElectionTick = *channelConfig.Params.Orderer.ETCDRaft.Options.ElectionTick
				}
				if channelConfig.Params.Orderer.ETCDRaft.Options.HeartbeatTick != nil {
					ordConfigtx.EtcdRaft.Options.HeartbeatTick = *channelConfig.Params.Orderer.ETCDRaft.Options.HeartbeatTick
				}
				if channelConfig.Params.Orderer.ETCDRaft.Options.MaxInflightBlocks != nil {
					ordConfigtx.EtcdRaft.Options.MaxInflightBlocks = *channelConfig.Params.Orderer.ETCDRaft.Options.MaxInflightBlocks
				}
				if channelConfig.Params.Orderer.ETCDRaft.Options.SnapshotIntervalSize != nil {
					ordConfigtx.EtcdRaft.Options.SnapshotIntervalSize = *channelConfig.Params.Orderer.ETCDRaft.Options.SnapshotIntervalSize
				}
			}
		}
	}
	configTXChannelConfig := configtx.Channel{
		Orderer:      ordConfigtx,
		Application:  application,
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
	if channelExists && saveOrderer {
		ordererAdminOrg := channelConfig.OrdererAdminOrgs[0]
		ordResClient, _, _, err := getResmgmtClient(sdk, ordererAdminOrg, configBackends)
		if err != nil {
			return err
		}
		_ = ordResClient
		cfgBlock, err := resource.ExtractConfigFromBlock(channelBlock)
		if err != nil {
			return errors.Wrapf(err, "failed to extract config from channel block")
		}
		updatedConfigTX := configtx.New(cfgBlock)
		err = updateOrdererChannelConfigTx(updatedConfigTX, configTXChannelConfig)
		if err != nil {
			return err
		}
		configUpdate, err := resmgmt.CalculateConfigUpdate(channelConfig.Name, cfgBlock, updatedConfigTX.UpdatedConfig())
		if err != nil {
			if !strings.Contains(err.Error(), "no differences detected between original and updated config") {
				return errors.Wrapf(err, "error calculating config update")
			}
			goto applicationUpdate
		}
		channelConfigBytes, err := CreateConfigUpdateEnvelope(channelConfig.Name, configUpdate)
		if err != nil {
			return errors.Wrapf(err, "error creating config update envelope")
		}
		configUpdateReader := bytes.NewReader(channelConfigBytes)
		var configSignatures []*cb.ConfigSignature
		for _, adminOrderer := range channelConfig.OrdererAdminOrgs {
			configUpdateReader = bytes.NewReader(channelConfigBytes)
			resClient, _, usr, err := getResmgmtClient(sdk, adminOrderer, configBackends)
			if err != nil {
				return err
			}
			signature, err := resClient.CreateConfigSignatureFromReader(usr, configUpdateReader)
			if err != nil {
				return err
			}
			configSignatures = append(configSignatures, signature)
		}
		configUpdateReader = bytes.NewReader(channelConfigBytes)
		saveChannelResponse, err := ordResClient.SaveChannel(
			resmgmt.SaveChannelRequest{
				ChannelID:         channelConfig.Name,
				ChannelConfig:     configUpdateReader,
				SigningIdentities: []msp.SigningIdentity{},
			},
			resmgmt.WithConfigSignatures(configSignatures...),
		)
		if err != nil {
			return errors.Wrapf(err, "error saving channel")
		}
		log.Infof("Orderer configuration updated with transaction ID: %s", saveChannelResponse.TransactionID)
	}
applicationUpdate:
	if channelExists && savePeer {
		peerAdminOrg := channelConfig.PeerAdminOrgs[0]
		peerResClient, _, _, err := getResmgmtClient(sdk, peerAdminOrg, configBackends)
		if err != nil {
			return err
		}
		cfgBlock, err := resource.ExtractConfigFromBlock(channelBlock)
		if err != nil {
			return errors.Wrapf(err, "failed to extract config from channel block")
		}
		updatedConfigTX := configtx.New(cfgBlock)
		err = updateApplicationChannelConfigTx(updatedConfigTX, configTXChannelConfig)
		if err != nil {
			return err
		}
		configUpdate, err := resmgmt.CalculateConfigUpdate(channelConfig.Name, cfgBlock, updatedConfigTX.UpdatedConfig())
		if err != nil {
			if !strings.Contains(err.Error(), "no differences detected between original and updated config") {
				return errors.Wrapf(err, "error calculating config update")
			}
			goto FINISH
		}
		channelConfigBytes, err := CreateConfigUpdateEnvelope(channelConfig.Name, configUpdate)
		if err != nil {
			return errors.Wrapf(err, "error creating config update envelope")
		}
		configUpdateReader := bytes.NewReader(channelConfigBytes)
		var configSignatures []*cb.ConfigSignature
		for _, adminPeer := range channelConfig.PeerAdminOrgs {
			configUpdateReader = bytes.NewReader(channelConfigBytes)
			peerResClient, _, usr, err := getResmgmtClient(sdk, adminPeer, configBackends)
			if err != nil {
				return err
			}
			signature, err := peerResClient.CreateConfigSignatureFromReader(usr, configUpdateReader)
			if err != nil {
				return err
			}
			configSignatures = append(configSignatures, signature)
		}
		configUpdateReader = bytes.NewReader(channelConfigBytes)
		saveChannelResponse, err := peerResClient.SaveChannel(
			resmgmt.SaveChannelRequest{
				ChannelID:         channelConfig.Name,
				ChannelConfig:     configUpdateReader,
				SigningIdentities: []msp.SigningIdentity{},
			},
			resmgmt.WithConfigSignatures(configSignatures...),
		)
		if err != nil {
			return errors.Wrapf(err, "error saving channel")
		}
		log.Infof("Application configuration updated with transaction ID: %s", saveChannelResponse.TransactionID)
	}
FINISH:
	return nil
}

func updateApplicationChannelConfigTx(currentConfigTX configtx.ConfigTx, newConfigTx configtx.Channel) error {

	err := currentConfigTX.Application().SetPolicies(
		newConfigTx.Application.Policies,
	)
	if err != nil {
		return errors.Wrapf(err, "failed to set application")
	}
	for _, peerOrg := range newConfigTx.Application.Organizations {
		err = currentConfigTX.Application().SetOrganization(peerOrg)
		if err != nil {
			return errors.Wrapf(err, "failed to set organization %s", peerOrg.Name)
		}
	}
	app, err := currentConfigTX.Application().Configuration()
	if err != nil {
		return errors.Wrapf(err, "failed to get application configuration")
	}

	for _, channelPeerOrg := range app.Organizations {
		deleted := true
		for _, organization := range newConfigTx.Application.Organizations {
			if organization.Name == channelPeerOrg.Name {
				deleted = false
				break
			}
		}
		if deleted {
			currentConfigTX.Application().RemoveOrganization(channelPeerOrg.Name)
		}
	}
	err = currentConfigTX.Application().SetACLs(
		newConfigTx.Application.ACLs,
	)
	if err != nil {
		return errors.Wrapf(err, "failed to set ACLs")
	}
	return nil
}
func mapPolicy(policy appconfig.Policy) configtx.Policy {
	return configtx.Policy{
		Type:      policy.Type,
		Rule:      policy.Rule,
		ModPolicy: policy.ModPolicy,
	}
}

func CreateConfigUpdateEnvelope(channelID string, configUpdate *cb.ConfigUpdate) ([]byte, error) {
	configUpdate.ChannelId = channelID
	configUpdateData, err := proto.Marshal(configUpdate)
	if err != nil {
		return nil, err
	}
	configUpdateEnvelope := &cb.ConfigUpdateEnvelope{}
	configUpdateEnvelope.ConfigUpdate = configUpdateData
	envelope, err := protoutil.CreateSignedEnvelope(cb.HeaderType_CONFIG_UPDATE, channelID, nil, configUpdateEnvelope, 0, 0)
	if err != nil {
		return nil, err
	}
	envelopeData, err := proto.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	return envelopeData, nil
}

func updateOrdererChannelConfigTx(currentConfigTX configtx.ConfigTx, newConfigTx configtx.Channel) error {
	err := currentConfigTX.Channel().SetPolicies(
		newConfigTx.Policies,
	)
	if err != nil {
		return errors.Wrapf(err, "failed to set policies")
	}
	if newConfigTx.ModPolicy != "" {
		err = currentConfigTX.Channel().SetModPolicy(
			newConfigTx.ModPolicy,
		)
		if err != nil {
			return errors.Wrapf(err, "failed to set policies")
		}
	}
	err = currentConfigTX.Orderer().SetConfiguration(
		newConfigTx.Orderer,
	)
	if err != nil {
		return errors.Wrapf(err, "failed to set batch size")
	}

	return nil
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
