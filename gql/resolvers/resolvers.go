package resolvers

// THIS CODE IS A STARTING POINT ONLY. IT WILL NOT BE UPDATED WITH SCHEMA CHANGES.

import (
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	appconfig "github.com/kfsoftware/hlf-channel-manager/config"
	"github.com/kfsoftware/hlf-channel-manager/gql"
	operatorv1 "github.com/kfsoftware/hlf-operator/pkg/client/clientset/versioned"
)

type Resolver struct {
	DCS                  map[string]*operatorv1.Clientset
	ChannelManagerConfig appconfig.HLFChannelManagerConfig
	FabricSDK            *fabsdk.FabricSDK
}

// Mutation returns gql.MutationResolver implementation.
func (r *Resolver) Mutation() gql.MutationResolver { return &mutationResolver{r} }

// Query returns gql.QueryResolver implementation.
func (r *Resolver) Query() gql.QueryResolver { return &queryResolver{r} }

type mutationResolver struct {
	*Resolver
}

type queryResolver struct{ *Resolver }
