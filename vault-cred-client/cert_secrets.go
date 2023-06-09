package vaultcredclient

import (
	"context"
	"strings"

	"github.com/intelops/go-common/vault-cred-client/vaultcredpb"
)

const (
	caDataKey   = "ca.pem"
	certDataKey = "cert.crt"
	keyDataKey  = "key.key"

	certCredentialType   = "certs"
	clientCertEntityName = "client"
)

type ClientCertificateData struct {
	CACert     string `json:"caCert"`
	ClientCert string `json:"clientCert"`
	ClientKey  string `json:"clientKey"`
}

type ClientCertReader interface {
	GetClientCertificateData(ctx context.Context, clientID string) (certData ClientCertificateData, err error)
}

type ClientCertAdmin interface {
	GetClientCertificateData(ctx context.Context, clientID string) (certData ClientCertificateData, err error)
	PutClientCertificateData(ctx context.Context, clientID string, certData ClientCertificateData) (err error)
	DeleteClientCertificateData(ctx context.Context, clientID string) (err error)
}

func NewClientCertReader() (ClientCertReader, error) {
	return newClient()
}

func NewClientCertAdmin() (ClientCertAdmin, error) {
	return newClient()
}

func (sc *client) GetClientCertificateData(ctx context.Context, clientID string) (ClientCertificateData, error) {
	request := vaultcredpb.GetCredRequest{
		CredentialType: certCredentialType,
		CredEntityName: clientCertEntityName,
		CredIdentifier: clientID,
	}

	cred, err := sc.c.GetCred(ctx, &request)
	if err != nil {
		return ClientCertificateData{}, err
	}

	serviceCred := ClientCertificateData{}
	for key, val := range cred.Credential {
		if strings.EqualFold(key, caDataKey) {
			serviceCred.CACert = val
		} else if strings.EqualFold(key, certDataKey) {
			serviceCred.ClientCert = val
		} else if strings.EqualFold(key, keyDataKey) {
			serviceCred.ClientKey = val
		}
	}
	return serviceCred, nil
}

func (sc *client) PutClientCertificateData(ctx context.Context, clientID string, certData ClientCertificateData) error {
	request := vaultcredpb.PutCredRequest{
		CredentialType: certCredentialType,
		CredEntityName: clientCertEntityName,
		CredIdentifier: clientID,
		Credential: map[string]string{caDataKey: certData.CACert,
			certDataKey: certData.ClientCert,
			keyDataKey:  certData.ClientKey},
	}

	_, err := sc.c.PutCred(ctx, &request)
	return err
}

func (sc *client) DeleteClientCertificateData(ctx context.Context, clientID string) error {
	request := vaultcredpb.DeleteCredRequest{
		CredentialType: certCredentialType,
		CredEntityName: clientCertEntityName,
		CredIdentifier: clientID,
	}

	_, err := sc.c.DeleteCred(ctx, &request)
	return err
}
