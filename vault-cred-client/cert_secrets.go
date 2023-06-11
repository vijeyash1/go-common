package vaultcredclient

import (
	"context"
	"strings"

	"github.com/intelops/go-common/vault-cred-client/vaultcredpb"
)

const (
	certCredentialType = "certs"

	CaptenClusterCert  = "capten-cluster"
	CustomerClientCert = "customer-client"
)

const (
	caDataKey   = "ca.pem"
	certDataKey = "cert.crt"
	keyDataKey  = "key.key"
)

type CertificateData struct {
	CACert string `json:"caCert"`
	Key    string `json:"key"`
	Cert   string `json:"cert"`
}

type CertificateReader interface {
	GetCertificate(ctx context.Context, certEntity, certIdentity string) (certData CertificateData, err error)
}

type CertificateAdmin interface {
	GetCertificate(ctx context.Context, certEntity, certIdentity string) (certData CertificateData, err error)
	StoreCertificate(ctx context.Context, certEntity, certIdentity string, certData CertificateData) (err error)
	DeleteCertificate(ctx context.Context, certEntity, certIdentity string) (err error)
}

func NewCertificateReader() (CertificateReader, error) {
	return newClient()
}

func NewCertificateAdmin() (CertificateAdmin, error) {
	return newClient()
}

func (sc *client) GetCertificate(ctx context.Context, certEntity, certIdentity string) (CertificateData, error) {
	request := vaultcredpb.GetCredRequest{
		CredentialType: certCredentialType,
		CredEntityName: certEntity,
		CredIdentifier: certIdentity,
	}

	cred, err := sc.c.GetCred(ctx, &request)
	if err != nil {
		return CertificateData{}, err
	}

	serviceCred := CertificateData{}
	for key, val := range cred.Credential {
		if strings.EqualFold(key, caDataKey) {
			serviceCred.CACert = val
		} else if strings.EqualFold(key, certDataKey) {
			serviceCred.Cert = val
		} else if strings.EqualFold(key, keyDataKey) {
			serviceCred.Key = val
		}
	}
	return serviceCred, nil
}

func (sc *client) StoreCertificate(ctx context.Context, certEntity, certIdentity string, certData CertificateData) error {
	request := vaultcredpb.PutCredRequest{
		CredentialType: certCredentialType,
		CredEntityName: certEntity,
		CredIdentifier: certIdentity,
		Credential: map[string]string{caDataKey: certData.CACert,
			certDataKey: certData.Cert,
			keyDataKey:  certData.Key},
	}

	_, err := sc.c.PutCred(ctx, &request)
	return err
}

func (sc *client) DeleteCertificate(ctx context.Context, certEntity, certIdentity string) error {
	request := vaultcredpb.DeleteCredRequest{
		CredentialType: certCredentialType,
		CredEntityName: certEntity,
		CredIdentifier: certIdentity,
	}

	_, err := sc.c.DeleteCred(ctx, &request)
	return err
}
