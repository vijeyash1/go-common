package vaultcredclient

import (
	"context"

	"github.com/intelops/go-common/vault-cred-client/vaultcredpb"
)

const (
	genericCredentialType = "generic"
)

type CredentialReader interface {
	GetCredential(ctx context.Context, entityName, credIdentifier string) (map[string]string, error)
}

type CredentialAdmin interface {
	GetCredential(ctx context.Context, entityName, credIdentifier string) (map[string]string, error)
	PutCredential(ctx context.Context, entityName, credIdentifier string, credential map[string]string) error
	DeleteCredential(ctx context.Context, entityName, credIdentifier string) error
}

func NewGenericCredentailReader() (c CredentialReader, err error) {
	return newClient()
}

func NewGerericCredentailAdmin() (c CredentialAdmin, err error) {
	return newClient()
}

func (sc *client) GetCredential(ctx context.Context, entityName, credIdentifier string) (map[string]string, error) {
	request := vaultcredpb.GetCredRequest{
		CredentialType: genericCredentialType,
		CredEntityName: entityName,
		CredIdentifier: credIdentifier,
	}

	cred, err := sc.c.GetCred(ctx, &request)
	if err != nil {
		return nil, err
	}

	credential := map[string]string{}
	for key, val := range cred.Credential {
		credential[key] = val
	}
	return credential, nil
}

func (sc *client) PutCredential(ctx context.Context, entityName, credIdentifier string, credential map[string]string) error {
	request := vaultcredpb.PutCredRequest{
		CredentialType: genericCredentialType,
		CredEntityName: entityName,
		CredIdentifier: credIdentifier,
		Credential:     map[string]string{},
	}

	for key, val := range credential {
		request.Credential[key] = val
	}

	_, err := sc.c.PutCred(ctx, &request)
	return err
}

func (sc *client) DeleteCredential(ctx context.Context, entityName, credIdentifier string) error {
	request := vaultcredpb.DeleteCredRequest{
		CredentialType: genericCredentialType,
		CredEntityName: entityName,
		CredIdentifier: credIdentifier,
	}
	_, err := sc.c.DeleteCred(ctx, &request)
	return err
}
