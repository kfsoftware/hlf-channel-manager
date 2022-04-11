package channel

import "github.com/spf13/cobra"

func NewChannelCMD() *cobra.Command {
	channelCmd := &cobra.Command{
		Use: "channel",
	}
	channelCmd.AddCommand(
		newSyncCMD(),
	)
	return channelCmd
}
