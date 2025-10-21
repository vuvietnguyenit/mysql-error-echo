/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"os"

	"log/slog"

	appflag "git.itim.vn/docker/mysql-response-trace/app/flag"
	"git.itim.vn/docker/mysql-response-trace/app/internal/ebpf"
	"github.com/spf13/cobra"
)

// runCmd represents the run command
var runCmd = &cobra.Command{
	Use:   "run",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		runProgram()
	},
}

func init() {
	rootCmd.AddCommand(runCmd)
	runCmd.PersistentFlags().Int16VarP(&appflag.Port, "port", "p", 3306, "MySQL server port you want to trace")
}

func runProgram() {
	err := ebpf.RunEbpfProg()
	if err != nil {
		slog.Error("failed to run eBPF program", err)
		os.Exit(1)
	}
}
