package cmd

import (
	"fmt"
	"github.com/gearnode/csp-handler/server"
	"github.com/spf13/cobra"
)

var conf serveConfig

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the HTTP server to handle CSP violation event",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		app := server.App{}
		app.Initialize()
		app.Run(fmt.Sprintf("%s:%s", conf.addr, conf.port))
	},
}

type serveConfig struct {
	addr string
	port string
}

func init() {
	rootCmd.AddCommand(serveCmd)

	serveCmd.Flags().StringVarP(&conf.addr, "bind", "b", "0.0.0.0", "binds csp-handler to the specified IP")
	serveCmd.Flags().StringVarP(&conf.port, "port", "p", "3000", "runs csp-handler on the specified port")
}
