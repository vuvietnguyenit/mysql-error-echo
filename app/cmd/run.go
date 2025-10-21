/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"os"

	"log/slog"

	appflag "git.itim.vn/docker/mysql-error-echo/app/flag"
	"git.itim.vn/docker/mysql-error-echo/app/internal/ebpf"
	"github.com/spf13/cobra"
)

// runCmd represents the run command
var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run the MySQL error response tracing program",
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
