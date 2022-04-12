package channel

import (
	"context"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	appconfig "github.com/kfsoftware/hlf-channel-manager/config"
	"github.com/kfsoftware/hlf-channel-manager/store/channel"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	"io/ioutil"
)

type syncCmd struct {
	config              string
	channelConfig       string
	hlfConfig           string
	outputPB            string
	outputJSON          string
	outputChannelUpdate string
	saveOrderer         bool
	savePeer            bool
}

func (c syncCmd) validate() error {
	return nil
}

func (c syncCmd) run() error {
	channelConfigBytes, err := ioutil.ReadFile(c.channelConfig)
	if err != nil {
		return err
	}
	channelConfig := appconfig.ChannelConfig{}
	err = yaml.Unmarshal(channelConfigBytes, &channelConfig)
	if err != nil {
		return err
	}
	channelManagerConfig := appconfig.HLFChannelManagerConfig{}
	hlfManagerConfigBytes, err := ioutil.ReadFile(c.config)
	if err != nil {
		return err
	}
	ctx := context.Background()
	err = yaml.Unmarshal(hlfManagerConfigBytes, &channelManagerConfig)
	if err != nil {
		return err
	}
	configBackend := config.FromFile(c.hlfConfig)
	sdk, err := fabsdk.New(configBackend)
	if err != nil {
		return err
	}
	coreBackends, err := configBackend()
	if err != nil {
		return err
	}
	_, err = channel.SyncChannel(
		ctx,
		channelConfig,
		map[string]*appconfig.DCClient{},
		sdk,
		coreBackends,
		c.saveOrderer,
		c.savePeer,
		false,
		false,
	)
	if err != nil {
		return err
	}
	return nil
}

func newSyncCMD() *cobra.Command {
	c := syncCmd{}
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Sync channel",
		Long:  "Sync channel",
		RunE: func(cmd *cobra.Command, args []string) error {
			err := c.validate()
			if err != nil {
				return err
			}
			return c.run()
		},
	}
	f := cmd.Flags()
	f.StringVarP(&c.config, "config", "f", "", "config file")
	f.StringVarP(&c.channelConfig, "channel-config", "c", "", "config file for the channel")
	f.StringVarP(&c.hlfConfig, "hlf-config", "", "", "hlf config to create/update the channel")
	f.StringVarP(&c.outputPB, "output-pb", "", "", "protocol buffer output")
	f.StringVarP(&c.outputJSON, "output-json", "", "", "protocol buffer json")
	f.StringVarP(&c.outputChannelUpdate, "output-update", "", "", "protocol buffer update channel")
	f.BoolVarP(&c.saveOrderer, "save-orderer", "", false, "update the orderer part of the channel")
	f.BoolVarP(&c.savePeer, "save-peer", "", false, "update the peer part of the channel")
	return cmd
}
