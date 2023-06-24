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

	log.Debugf("test debug %s", logging.MaskString("arg1"))
	log.Debugf("test debug %s", logging.MaskString(""))

	u := struct {
		ID      string // no tag
		Name    string
		Token   string
		ExtData map[string]string
	}{
		ID:    "1",
		Name:  "testuser",
		Token: "valtokne",
		ExtData: map[string]string{
			"Email": "test@com",
		},
	}

	logging.RegisterMaskField("Token")
	logging.RegisterMaskField("Email")
	mu, _ := logging.Mask(u)
	log.Debugf("%v", mu)
}
