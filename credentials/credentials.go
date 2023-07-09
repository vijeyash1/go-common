package credentials

import (
	"context"
	"strings"
)

const (
	serviceCredentialType        = "service-cred"
	serviceCredentialUserNameKey = "userName"
	serviceCredentialPasswordKey = "password"

	certCredentialType = "certs"
	caDataKey          = "ca.crt"
	certDataKey        = "tls.crt"
	keyDataKey         = "tls.key"
)

type ServiceCredentail struct {
	UserName       string            `json:"userName"`
	Password       string            `json:"password"`
	AdditionalData map[string]string `json:"additionalData"`
}

type CertificateData struct {
	CACert string `json:"ca.crt"`
	Key    string `json:"tls.crt"`
	Cert   string `json:"tls.key"`
}

type CredentialReader interface {
	GetCredential(ctx context.Context, credentialType, entityName, credentialIdentifier string) (map[string]string, error)
	GetServiceUserCredential(ctx context.Context, entityName, credentialIdentifier string) (ServiceCredentail, error)
	GetCertificateData(ctx context.Context, entityName, credentialIdentifier string) (CertificateData, error)
}

type CredentialAdmin interface {
	GetCredential(ctx context.Context, credentialType, entityName, credentialIdentifier string) (map[string]string, error)
	GetServiceUserCredential(ctx context.Context, entityName, credentialIdentifier string) (ServiceCredentail, error)
	PutCredential(ctx context.Context, credentialType, entityName, credentialIdentifier string, credential map[string]string) error
	PutServiceUserCredential(ctx context.Context, entityName, credentialIdentifier string, serviceUserCred ServiceCredentail) error
	PutCertificateData(ctx context.Context, entityName, credentialIdentifier string, certData CertificateData) error
	DeleteCredential(ctx context.Context, credentialType, entityName, credentialIdentifier string) error
	DeleteServiceUserCredential(ctx context.Context, entityName, credentialIdentifier string) error
	DeleteCertificateData(ctx context.Context, entityName, credentialIdentifier string) error
}

func NewCredentailReader(ctx context.Context) (c CredentialReader, err error) {
	return newClientWithAuth(ctx)
}

func NewCredentailAdmin(ctx context.Context) (c CredentialAdmin, err error) {
	return newClientWithAuth(ctx)
}

func (vc *client) GetCredential(ctx context.Context, credentialType, entityName, credentialIdentifier string) (map[string]string, error) {
	secretPath := prepareCredentialSecretPath(credentialType, entityName, credentialIdentifier)
	credential, err := vc.getCredential(ctx, secretPath)
	if err != nil {
		return nil, err
	}
	return credential, nil
}

func (vc *client) PutCredential(ctx context.Context, credentialType, entityName, credentialIdentifier string, credential map[string]string) error {
	secretPath := prepareCredentialSecretPath(credentialType, entityName, credentialIdentifier)
	return vc.putCredential(ctx, secretPath, credential)
}

func (vc *client) DeleteCredential(ctx context.Context, credentialType, entityName, credentialIdentifier string) error {
	secretPath := prepareCredentialSecretPath(credentialType, entityName, credentialIdentifier)
	return vc.deleteCredential(ctx, secretPath)
}

func (vc *client) GetServiceUserCredential(ctx context.Context, entityName, credentialIdentifier string) (ServiceCredentail, error) {
	secretPath := prepareCredentialSecretPath(serviceCredentialType, entityName, credentialIdentifier)
	credential, err := vc.getCredential(ctx, secretPath)
	if err != nil {
		return ServiceCredentail{}, err
	}

	serviceUserCred := ServiceCredentail{
		AdditionalData: map[string]string{},
	}

	for key, val := range credential {
		if strings.EqualFold(key, serviceCredentialUserNameKey) {
			serviceUserCred.UserName = val
		} else if strings.EqualFold(key, serviceCredentialPasswordKey) {
			serviceUserCred.Password = val
		} else {
			serviceUserCred.AdditionalData[key] = val
		}
	}
	return serviceUserCred, nil
}

func (vc *client) PutServiceUserCredential(ctx context.Context, entityName, credentialIdentifier string, serviceUserCred ServiceCredentail) error {
	secretPath := prepareCredentialSecretPath(serviceCredentialType, entityName, credentialIdentifier)
	credential := map[string]string{
		serviceCredentialUserNameKey: serviceUserCred.UserName,
		serviceCredentialPasswordKey: serviceUserCred.Password}

	for key, val := range serviceUserCred.AdditionalData {
		credential[key] = val
	}
	return vc.putCredential(ctx, secretPath, credential)
}

func (vc *client) DeleteServiceUserCredential(ctx context.Context, entityName, credentialIdentifier string) error {
	secretPath := prepareCredentialSecretPath(serviceCredentialType, entityName, credentialIdentifier)
	return vc.deleteCredential(ctx, secretPath)
}

func (vc *client) GetCertificateData(ctx context.Context, entityName, credentialIdentifier string) (CertificateData, error) {
	secretPath := prepareCredentialSecretPath(certCredentialType, entityName, credentialIdentifier)
	credential, err := vc.getCredential(ctx, secretPath)
	if err != nil {
		return CertificateData{}, err
	}

	certData := CertificateData{}
	for key, val := range credential {
		if strings.EqualFold(key, caDataKey) {
			certData.CACert = val
		} else if strings.EqualFold(key, certDataKey) {
			certData.Cert = val
		} else if strings.EqualFold(key, keyDataKey) {
			certData.Key = val
		}
	}
	return certData, nil
}

func (vc *client) PutCertificateData(ctx context.Context, entityName, credentialIdentifier string, certData CertificateData) error {
	secretPath := prepareCredentialSecretPath(certCredentialType, entityName, credentialIdentifier)
	credential := map[string]string{caDataKey: certData.CACert,
		certDataKey: certData.Cert,
		keyDataKey:  certData.Key}
	return vc.putCredential(ctx, secretPath, credential)
}

func (vc *client) DeleteCertificateData(ctx context.Context, entityName, credentialIdentifier string) error {
	secretPath := prepareCredentialSecretPath(certCredentialType, entityName, credentialIdentifier)
	return vc.deleteCredential(ctx, secretPath)
}
