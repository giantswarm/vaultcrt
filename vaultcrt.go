package vaultcrt

import (
	"github.com/giantswarm/microerror"
	"github.com/giantswarm/micrologger"
	vaultclient "github.com/hashicorp/vault/api"
)

type Config struct {
	Logger      micrologger.Logger
	VaultClient *vaultclient.Client

	CommonNameFormat string
}

func DefaultConfig() Config {
	config := Config{
		Logger:      nil,
		VaultClient: nil,

		CommonNameFormat: "",
	}

	return config
}

type VaultCrt struct {
	logger      micrologger.Logger
	vaultClient *vaultclient.Client

	commonNameFormat string
}

func New(config Config) (*VaultCrt, error) {
	if config.Logger == nil {
		return nil, microerror.Maskf(invalidConfigError, "config.Logger must not be empty")
	}
	if config.VaultClient == nil {
		return nil, microerror.Maskf(invalidConfigError, "config.VaultClient must not be empty")
	}

	if config.CommonNameFormat == "" {
		return nil, microerror.Maskf(invalidConfigError, "config.CommonNameFormat must not be empty")
	}

	c := &VaultCrt{
		logger:      config.Logger,
		vaultClient: config.VaultClient,

		commonNameFormat: config.CommonNameFormat,
	}

	return c, nil
}
