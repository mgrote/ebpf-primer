package cmd

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"ebpf-primer/ebpf/packetcount"
	"ebpf-primer/log"
)

const (
	VNetworkInterface = "viper.ebpf.networkInterface"

	FlagNetworkInterface = "network-interface"

	EnvNetworkInterface = "EBPF_NETWORK_INTERFACE"
)

var (
	packetCounterViperMappings = []ViperMapping{
		{
			Name:           "Network interface",
			ViperIndicator: VNetworkInterface,
			FlagIndicator:  FlagNetworkInterface,
			EnvIndicator:   EnvNetworkInterface,
			Description:    "network interface to monitor",
		},
	}
	packetCoundCmd = &cobra.Command{
		Use:   "packet-count",
		Short: "run packet count on interface",
		Long:  "run packet count ebpf program on interface",
		Run: func(cmd *cobra.Command, args []string) {
			log.Logger.V(2).Info("running ebpf count command")
			if err := checkConfig(packetCounterViperMappings...); err != nil {
				log.Logger.Error(err, "Packet count check config")
				os.Exit(1)
			}
			if err := packetcount.PacketCount(viper.GetString(VNetworkInterface)); err != nil {
				log.Logger.Error(err, "error loading program")
				os.Exit(1)
			}
		},
	}
)

func init() {
	initFlagsAndEnv(packetCoundCmd, packetCounterViperMappings)
	ebpfRootCmd.AddCommand(packetCoundCmd)
}
