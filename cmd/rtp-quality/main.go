// Command rtp-quality measures RTP jitter, packet loss and estimated MOS from a packet capture.
package main

import (
	"os"

	"github.com/ErenOzgu/rtp-quality/internal/cli"
)

// version is set at build time: -ldflags "-X main.version=v0.1.0".
var version = "dev"

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, version))
}
