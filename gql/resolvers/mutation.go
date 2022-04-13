package resolvers

import (
	"context"
	appconfig "github.com/kfsoftware/hlf-channel-manager/config"
	"github.com/kfsoftware/hlf-channel-manager/gql/models"
	"github.com/kfsoftware/hlf-channel-manager/store/channel"
	"gopkg.in/yaml.v3"
)

func (r *mutationResolver) SyncChannel(
	ctx context.Context,
	channelConfigStr string,
	saveOrderer bool,
	saveApplication bool,
	joinOrderers bool,
	joinPeers bool,
) (*models.SyncChannelResponse, error) {
	channelConfig := appconfig.ChannelConfig{}
	err := yaml.Unmarshal([]byte(channelConfigStr), &channelConfig)
	if err != nil {
		return nil, err
	}
	res, err := channel.SyncChannel(
		ctx,
		channelConfig,
		r.DCS,
		r.FabricSDK,
		r.ConfigBackend,
		saveOrderer,
		saveApplication,
		joinOrderers,
		joinPeers,
	)
	if err != nil {
		return nil, err
	}
	return &models.SyncChannelResponse{
		Success:         true,
		ApplicationTxID: res.ApplicationTxId,
		OrdererTxID:     res.OrdererTxId,
		OrderersJoined:  res.OrderersJoined,
		PeersJoined:     res.PeersJoined,
	}, nil

}
