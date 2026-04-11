package websession

import (
	"log"

	"github.com/borghives/kosmos-go/ether"
)

type Constants struct {
	SecretSession string `mapstructure:"SECRET_SESSION"`
	SiteDomain    string `mapstructure:"SITE_DOMAIN"`
	Port          string `mapstructure:"PORT"`
}

var EtherialConstants ether.LiminalStructure[Constants]

func CollapseConstants() Constants {
	constants := EtherialConstants.Collapse()
	if constants.SiteDomain == "" {
		constants.SiteDomain = "localhost"
	}
	if constants.SecretSession == "" {
		log.Fatal("missing secret for SessionManager")
	}
	if constants.Port == "" {
		constants.Port = "8080"
	}
	return constants
}

func init() {
	ether.RegisterLiminalStructure(&EtherialConstants)
}
