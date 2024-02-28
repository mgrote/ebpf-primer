package cmd

import (
	"flag"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"ebpf-primer/log"
)

var (
	cfgFile              string
	genericViperMappings []ViperMapping
)

type ViperMapping struct {
	Name           string
	ViperIndicator string
	FlagIndicator  string
	EnvIndicator   string
	Description    string
}

var ebpfRootCmd = &cobra.Command{
	Use:   "ebpfctl",
	Short: "A CLI tool to manage eBPF programs and maps.",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("root command")
		log.Logger.V(2).WithName("mainCommand").Info("main command, may you want to init config and run controller here")
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the ebpfRootCmd.
func Execute() {
	if err := ebpfRootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	flag.CommandLine.Set("v", "2")
	flag.Parse()
	cobra.OnInitialize(initConfig)
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	}
	viper.AutomaticEnv() // read in environment variables that match
}

func initFlagsAndEnv(cmd *cobra.Command, mappings []ViperMapping) {
	for _, mapping := range mappings {
		// declare flags provided by cobra
		cmd.PersistentFlags().String(mapping.FlagIndicator, "", mapping.Description)
		// bind flags to viper
		if err := viper.BindPFlag(mapping.ViperIndicator, cmd.PersistentFlags().Lookup(mapping.FlagIndicator)); err != nil {
			log.Logger.WithValues("flagname", mapping.FlagIndicator).Error(err, "could not bind to viper, flag is not defined.")
		}
		// bind environment to viper
		if err := viper.BindEnv(mapping.ViperIndicator, mapping.EnvIndicator); err != nil {
			log.Logger.WithValues("envname", mapping.EnvIndicator).Error(err, "could not bind to viper, environment variable is not defined.")
		}
	}
}

func checkConfig(additional ...ViperMapping) error {
	mappings := append(genericViperMappings, additional...)
	for _, mapping := range mappings {
		if viper.GetString(mapping.ViperIndicator) == "" {
			log.Logger.Error(nil, "Not all expected config parameters could be read.", "missing flag", mapping.FlagIndicator, "missing env", mapping.EnvIndicator)
			return fmt.Errorf("missing flag %s or env %s", mapping.FlagIndicator, mapping.EnvIndicator)
		}
	}
	return nil
}
