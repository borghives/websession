package websession

import "github.com/borghives/kosmos-go/ether"

type Constants struct {
	SecretSession string `mapstructure:"SECRET_SESSION"`
	SiteDomain    string `mapstructure:"SITE_DOMAIN"`
}

var EtherialConstants ether.LiminalStructure[Constants]

func CollapseConstants() Constants {
	constants := EtherialConstants.Collapse()
	if constants.SiteDomain == "" {
		constants.SiteDomain = "localhost"
	}
	return constants
}

func init() {
	ether.RegisterLiminalStructure(&EtherialConstants)
}
