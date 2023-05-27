package vaultcredclient

import (
	"os"

	"github.com/intelops/go-common/vault-cred-client/vaultcredpb"
	"github.com/kelseyhightower/envconfig"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type config struct {
	VaultCredService       string `envconfig:"VAULT_CRED_SERVICE" required:"true"`
	VaultRole              string `envconfig:"VAULT_ROLE" required:"true"`
	ServiceAccoutTokenPath string `envconfig:"SERVICE_ACCOUNT_TOKEN_PATH" default:"/var/run/secrets/kubernetes.io/serviceaccount/token"`
}

type client struct {
	c     vaultcredpb.VaultCredClient
	conf  config
	token string
}

func newClient() (*client, error) {
	cfg := config{}
	if err := envconfig.Process("", &cfg); err != nil {
		return nil, err
	}

	token, err := readFileContent(cfg.ServiceAccoutTokenPath)
	if err != nil {
		return nil, err
	}

	conn, err := grpc.Dial(cfg.VaultCredService, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}

	c := vaultcredpb.NewVaultCredClient(conn)
	return &client{c: c, conf: cfg, token: token}, nil
}

func readFileContent(path string) (s string, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	s = string(b)
	return
}
