package vaultcredclient

import (
	"context"

	"github.com/intelops/go-common/vault-cred-client/vaultcredpb"
)

const (
	genericCredentialType = "cluster-cred"
)

type GerericCredentail struct {
	Credential map[string]string `json:"credential"`
}

type GenericCredentialReader interface {
	GetGenericCredential(ctx context.Context, svcEntity, userName string) (cred GerericCredentail, err error)
}

type GerericCredentialAdmin interface {
	GetGenericCredential(ctx context.Context, svcEntity, userName string) (cred GerericCredentail, err error)
	PutGenericCredential(ctx context.Context, svcEntity, userName string, cred GerericCredentail) (err error)
	DeleteGerericCredential(ctx context.Context, svcEntity, userName string) (err error)
}

func NewGenericCredentailReader() (c GenericCredentialReader, err error) {
	return newClient()
}

func NewGerericCredentailAdmin() (c GerericCredentialAdmin, err error) {
	return newClient()
}

func (sc *client) GetGenericCredential(ctx context.Context, genericEntity, credIdentifier string) (GerericCredentail, error) {
	request := vaultcredpb.GetCredRequest{
		CredentialType: genericCredentialType,
		CredEntityName: genericEntity,
		CredIdentifier: credIdentifier,
	}

	cred, err := sc.c.GetCred(ctx, &request)
	if err != nil {
		return GerericCredentail{}, err
	}

	gerericCred := GerericCredentail{
		Credential: map[string]string{},
	}

	for key, val := range cred.Credential {
		gerericCred.Credential[key] = val
	}
	return gerericCred, nil
}

func (sc *client) PutGenericCredential(ctx context.Context, genericEntity, credIdentifier string, genericCred GerericCredentail) error {
	request := vaultcredpb.PutCredRequest{
		CredentialType: genericCredentialType,
		CredEntityName: genericEntity,
		CredIdentifier: credIdentifier,
	}

	for key, val := range genericCred.Credential {
		request.Credential[key] = val
	}

	_, err := sc.c.PutCred(ctx, &request)
	return err
}

func (sc *client) DeleteGerericCredential(ctx context.Context, genericEntity, credIdentifier string) error {
	request := vaultcredpb.DeleteCredRequest{
		CredentialType: serviceCredentialType,
		CredEntityName: genericEntity,
		CredIdentifier: credIdentifier,
	}
	_, err := sc.c.DeleteCred(ctx, &request)
	return err
}
