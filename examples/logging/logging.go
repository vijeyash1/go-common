package main

import (
	"os"

	"github.com/intelops/go-common/logging"
)

func main() {
	_ = os.Setenv("LOG_LEVEL", "info")
	log := logging.NewLogger()
	log.Info("test info")
	log.Debug("test debug")

	_ = os.Setenv("LOG_LEVEL", "debug")
	log = logging.NewLogger()
	log.Info("test info %s", "arg1")
	log.Debug("test debug")
	log.Debugf("test debug %s", "arg1")

}
