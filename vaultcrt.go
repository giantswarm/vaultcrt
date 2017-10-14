package vaultcrt

import (
	"github.com/giantswarm/microerror"
	vaultclient "github.com/hashicorp/vault/api"
)

type Config struct {
	VaultClient *vaultclient.Client
}

func DefaultConfig() Config {
	config := Config{
		VaultClient: nil,
	}

	return config
}

type VaultCrt struct {
	vaultClient *vaultclient.Client
}

func New(config Config) (*VaultCrt, error) {
	if config.VaultClient == nil {
		return nil, microerror.Maskf(invalidConfigError, "config.VaultClient must not be empty")
	}

	c := &VaultCrt{
		vaultClient: config.VaultClient,
	}

	return c, nil
}
