package vault

import (
	"context"
	"os"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/hashicorp/vault/api"
	vaultauth "github.com/hashicorp/vault/api/auth/kubernetes"
	"github.com/intelops/go-common/logging"
	"github.com/kelseyhightower/envconfig"
	"github.com/pkg/errors"
)

type vaultEnv struct {
	Address           string        `envconfig:"VAULT_ADDR" required:"true"`
	Role              string        `envconfig:"VAULT_ROLE" required:"true"`
	CACert            string        `envconfig:"VAULT_CACERT" required:"true"`
	JwtTokenPath      string        `envconfig:"VAULT_K8S_SA_TOKEN_PATH" default:"/var/run/secrets/kubernetes.io/serviceaccount/token"`
	TokenPath         string        `envconfig:"VAULT_TOKEN_PATH"`
	ReadTimeout       time.Duration `envconfig:"VAULT_READ_TIMEOUT" default:"60s"`
	MaxRetries        int           `envconfig:"VAULT_MAX_RETRIES" default:"5"`
	ServiceSecretPath string        `envconfig:"VAULT_SERVICE_SECRET_PATH" default:"secret/sas/service/"`
	CertSecretPath    string        `envconfig:"VAULT_CERT_SECRET_PATH" default:"secret/sas/cert/"`
}

type client struct {
	conf *vaultEnv
	vc   *api.Client
}

func getVaultEnv() (*vaultEnv, error) {
	cfg := &vaultEnv{}
	if err := envconfig.Process("", cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func mustNewClient(log logging.Logger) *client {
	c, err := newClient()
	if err != nil {
		log.Fatalf("failed to create client, %w", err)
	}
	return c
}

func newClient() (c *client, err error) {
	conf, err := getVaultEnv()
	if err != nil {
		return nil, err
	}

	cfg, err := prepareVaultConfig(conf)
	if err != nil {
		return nil, err
	}

	vc, err := api.NewClient(cfg)
	if err != nil {
		return nil, err
	}

	err = configureAuthToken(vc, conf)
	if err != nil {
		return nil, err
	}

	c = &client{
		vc:   vc,
		conf: conf,
	}
	return
}

func prepareVaultConfig(conf *vaultEnv) (cfg *api.Config, err error) {
	cfg = api.DefaultConfig()
	cfg.Address = conf.Address
	cfg.Timeout = conf.ReadTimeout
	cfg.Backoff = retryablehttp.DefaultBackoff
	cfg.MaxRetries = conf.MaxRetries
	tlsConfig := api.TLSConfig{CACert: conf.CACert}
	err = cfg.ConfigureTLS(&tlsConfig)
	return
}

func configureAuthToken(vc *api.Client, conf *vaultEnv) (err error) {
	if conf.TokenPath != "" {
		token, err := readFileContent(conf.TokenPath)
		if err != nil {
			return errors.WithMessage(err, "error in reading token file")
		}
		vc.SetToken(token)
		return nil
	}

	k8sAuth, err := vaultauth.NewKubernetesAuth(
		conf.Role,
		vaultauth.WithServiceAccountTokenPath(conf.JwtTokenPath),
	)
	if err != nil {
		return errors.WithMessagef(err, "error in initializing Kubernetes auth method")
	}

	authInfo, err := vc.Auth().Login(context.Background(), k8sAuth)
	if err != nil {
		return errors.WithMessagef(err, "error in login with Kubernetes auth")
	}
	if authInfo == nil {
		return errors.New("no auth info was returned after login")
	}
	return nil
}

func readFileContent(path string) (s string, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	s = string(b)
	return
}
