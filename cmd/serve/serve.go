package serve

import (
	"context"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	appconfig "github.com/kfsoftware/hlf-channel-manager/config"
	"github.com/kfsoftware/hlf-channel-manager/log"
	"github.com/kfsoftware/hlf-channel-manager/server"
	operatorv1 "github.com/kfsoftware/hlf-operator/pkg/client/clientset/versioned"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	serveDesc = `
'serve' command starts the server API`
	serveExample = `hlf-channel-manager serve --address="0.0.0.0:8080" --config=./config.yaml`
)

type serveCmd struct {
	address        string
	metricsAddress string
	config         string
	hlfConfig      string
}

func NewServeCmd() *cobra.Command {
	s := &serveCmd{}
	cmd := &cobra.Command{
		Use:     "serve",
		Short:   "Starts the server",
		Long:    serveDesc,
		Example: serveExample,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := s.validate(); err != nil {
				return err
			}
			return s.run()
		},
	}

	f := cmd.Flags()
	f.StringVar(&s.address, "address", "", "address for the server")
	f.StringVar(&s.metricsAddress, "metrics-address", "", "address for the metrics server")
	f.StringVar(&s.config, "config", "", "path to the config file")
	f.StringVar(&s.hlfConfig, "hlf-config", "", "path to the hlf config")
	return cmd
}

func (c *serveCmd) validate() error {
	if c.address == "" {
		return errors.New("--address is required for the server")
	}
	if c.metricsAddress == "" {
		return errors.New("--metrics-address is required for the server")
	}
	if c.config == "" {
		return errors.New("--config is required for the server")
	}
	if c.hlfConfig == "" {
		return errors.New("--hlf-config is required for the server")
	}
	return nil
}

func (c *serveCmd) run() error {
	ctx := context.Background()
	channelManagerConfig := appconfig.HLFChannelManagerConfig{}
	hlfManagerConfigBytes, err := ioutil.ReadFile(c.config)
	if err != nil {
		return err
	}
	err = yaml.Unmarshal(hlfManagerConfigBytes, &channelManagerConfig)
	if err != nil {
		return err
	}
	dcs := map[string]*operatorv1.Clientset{}
	for _, dc := range channelManagerConfig.DCs {
		restConfig, err := clientcmd.BuildConfigFromFlags("", dc.KubeConfig)
		if err != nil {
			log.Errorf("failed to build config from %v", err)
			return err
		}
		hlfClient, err := operatorv1.NewForConfig(restConfig)
		if err != nil {
			log.Errorf("failed to build hlf client from %v", err)
			return err
		}
		dcs[dc.Name] = hlfClient
	}
	configBackend := config.FromFile(c.hlfConfig)
	sdk, err := fabsdk.New(configBackend)
	if err != nil {
		return err
	}
	opts := server.BlockchainServerOpts{
		DCS:                  dcs,
		FabricSDK:            sdk,
		ChannelManagerConfig: channelManagerConfig,
		Address:              c.address,
		MetricsAddress:       c.metricsAddress,
	}
	s := server.NewServer(ctx, opts)
	s.Run()
	return nil
}
