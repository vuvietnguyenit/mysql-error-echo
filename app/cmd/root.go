/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"log/slog"
	"os"

	appflag "git.itim.vn/docker/mysql-response-trace/app/flag"
	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "mysql-response-trace",
	Short: "A brief description of your application",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Default level = INFO
		level := slog.LevelInfo
		if appflag.Verbose {
			level = slog.LevelDebug
		}
		logger := slog.New(
			slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
				Level: level, // global level
			}),
		)
		slog.SetDefault(logger)
		// if err := rlimit.RemoveMemlock(); err != nil {
		// 	return err
		// } else {
		// 	slog.Debug("set rlimit memlock to infinity")
		// }
		return nil
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&appflag.Verbose, "verbose", "v", false, "verbose output print")
}
