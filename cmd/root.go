/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"github.com/kfsoftware/hlf-channel-manager/cmd/channel"
	"github.com/kfsoftware/hlf-channel-manager/cmd/serve"
	"github.com/spf13/cobra"
)

func NewRootCMD() *cobra.Command {
	// rootCmd represents the base command when called without any subcommands
	var rootCmd = &cobra.Command{
		Use:   "hlf-channel-manager",
		Short: "A brief description of your application",
		Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}
	rootCmd.AddCommand(
		serve.NewServeCmd(),
		channel.NewChannelCMD(),
	)
	return rootCmd
}
