/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"log/slog"
	"os"

	appflag "git.itim.vn/docker/mysql-error-echo/app/flag"
	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "mysql-error-echo",
	Short: "eBPF to help trace MySQL error responses at the kernel level",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Default level = INFO
		level := slog.LevelInfo
		if appflag.Verbose {
			level = slog.LevelDebug
		}
		logger := slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
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
