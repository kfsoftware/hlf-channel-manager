package resolvers

import (
	"bytes"
	"context"
	"github.com/hyperledger/fabric-config/protolator"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/ledger"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/resmgmt"
	"github.com/hyperledger/fabric-sdk-go/pkg/fab/resource"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	"github.com/kfsoftware/hlf-channel-manager/gql/models"
	"github.com/pkg/errors"
)

func (r *queryResolver) Channel(ctx context.Context, name string, mspID string, user string) (*models.Channel, error) {
	sdkContext := r.FabricSDK.Context(
		fabsdk.WithUser("admin"),
		fabsdk.WithOrg("euipomsp"),
	)
	resClient, err := resmgmt.New(sdkContext)
	if err != nil {
		return nil, err
	}
	blck, err := resClient.QueryConfigBlockFromOrderer(name)
	if err != nil {
		return nil, err
	}
	cfgBlock, err := resource.ExtractConfigFromBlock(blck)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to extract config from channel block")
	}
	var buffer bytes.Buffer
	err = protolator.DeepMarshalJSON(&buffer, cfgBlock)
	if err != nil {
		return nil, err
	}
	channelProvider := r.FabricSDK.ChannelContext(
		name,
		fabsdk.WithUser("admin"),
		fabsdk.WithOrg("euipomsp"),
	)
	ledgerClient, err := ledger.New(channelProvider)
	if err != nil {
		return nil, err
	}
	info, err := ledgerClient.QueryInfo()
	if err != nil {
		return nil, err
	}
	height := info.BCI.Height
	return &models.Channel{
		Name:   name,
		Height: int(height),
		Config: buffer.String(),
	}, nil
}

func (r *queryResolver) Orgs(ctx context.Context) ([]*models.Org, error) {
	//TODO implement me
	panic("implement me")
}

func (r *queryResolver) Org(ctx context.Context, mspID string) (*models.Org, error) {
	//TODO implement me
	panic("implement me")
}
