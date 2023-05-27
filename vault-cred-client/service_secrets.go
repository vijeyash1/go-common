package vaultcredclient

import (
	"context"
	"strings"

	"github.com/intelops/go-common/vault-cred-client/vaultcredpb"
)

const (
	serviceCredentialType = "service-cred"

	serviceCredentialUserNameKey = "userName"
	serviceCredentialPasswordKey = "password"
)

type ServiceCredentail struct {
	UserName       string            `json:"userName"`
	Password       string            `json:"password"`
	AdditionalData map[string]string `json:"additionalData"`
}

type ServiceCredentialReader interface {
	GetServiceCredential(ctx context.Context, userName string, entityName string) (cred ServiceCredentail, err error)
}

type ServiceCredentialAdmin interface {
	GetServiceCredential(ctx context.Context, userName string, entityName string) (cred ServiceCredentail, err error)
	PutServiceCredential(ctx context.Context, userName string, entityName string, cred ServiceCredentail) (err error)
	DeleteServiceCredential(ctx context.Context, userName string, entityName string) (err error)
}

func NewServiceCredentailReader() (c ServiceCredentialReader, err error) {
	return newClient()
}

func NewServiceCredentailAdmin() (c ServiceCredentialAdmin, err error) {
	return newClient()
}

func (sc *client) GetServiceCredential(ctx context.Context, userName string, entityName string) (ServiceCredentail, error) {
	request := vaultcredpb.GetCredRequest{
		CredentialType:      serviceCredentialType,
		CredEntityName:      entityName,
		CredIdentifier:      userName,
		ServiceAccountToken: sc.token,
		VaultRole:           sc.conf.VaultRole,
	}

	cred, err := sc.c.GetCred(ctx, &request)
	if err != nil {
		return ServiceCredentail{}, err
	}

	serviceCred := ServiceCredentail{
		AdditionalData: map[string]string{},
	}

	for key, val := range cred.Credentail {
		if strings.EqualFold(key, serviceCredentialUserNameKey) {
			serviceCred.UserName = val
		} else if strings.EqualFold(key, serviceCredentialPasswordKey) {
			serviceCred.Password = val
		} else {
			serviceCred.AdditionalData[key] = val
		}
	}
	return serviceCred, nil
}

func (sc *client) PutServiceCredential(ctx context.Context, userName string, entityName string, serviceCred ServiceCredentail) error {
	request := vaultcredpb.PutCredRequest{
		CredentialType:      serviceCredentialType,
		CredEntityName:      entityName,
		CredIdentifier:      userName,
		ServiceAccountToken: sc.token,
		VaultRole:           sc.conf.VaultRole,
		Credentail: map[string]string{serviceCredentialUserNameKey: serviceCred.UserName,
			serviceCredentialPasswordKey: serviceCred.Password},
	}

	for key, val := range serviceCred.AdditionalData {
		request.Credentail[key] = val
	}

	_, err := sc.c.PutCred(ctx, &request)
	return err
}

func (sc *client) DeleteServiceCredential(ctx context.Context, entityName string, userName string) error {
	request := vaultcredpb.DeleteCredRequest{
		CredentialType:      serviceCredentialType,
		CredEntityName:      entityName,
		CredIdentifier:      userName,
		ServiceAccountToken: sc.token,
		VaultRole:           sc.conf.VaultRole,
	}
	_, err := sc.c.DeleteCred(ctx, &request)
	return err
}
