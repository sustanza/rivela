package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string

	// rootCmd points to the main Rivela command
	rootCmd = RivelaCmd
)

// Execute executes the root command.
func Execute() {
       if err := rootCmd.Execute(); err != nil {
               fmt.Fprintln(os.Stderr, err)
               os.Exit(1)
       }
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global / persistent config file flag
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "",
		"config file (default is $HOME/.rivela.yaml)")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.AddConfigPath("$HOME")
		viper.SetConfigName(".rivela")
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}
