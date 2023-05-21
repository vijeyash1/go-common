package vault

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/intelops/go-common/logging"
	"github.com/pkg/errors"
)

const (
	serviceCredentailDatakey = "SERVICE_USER_CRED"
)

type ServiceCredentail struct {
	UserName       string            `json:"userName"`
	Password       string            `json:"password"`
	AdditionalData map[string]string `json:"additionalData"`
}

type ServiceCredentialReader interface {
	GetServiceCredential(ctx context.Context, userName string, serviceType string) (cred ServiceCredentail, err error)
	GetClientCertificateData(ctx context.Context, clientID string) (certData CertificateData, err error)
}

type ServiceCredentialAdmin interface {
	GetServiceCredential(ctx context.Context, userName string, serviceType string) (cred ServiceCredentail, err error)
	PutServiceCredential(ctx context.Context, userName string, serviceType string, cred ServiceCredentail) (err error)
	DeleteServiceCredential(ctx context.Context, userName string, serviceType string) (err error)
}

func NewServiceCredentailReader() (c ServiceCredentialReader, err error) {
	return newClient()
}

func NewServiceCredentialAdmin() (ServiceCredentialAdmin, error) {
	return newClient()
}

func MustNewServiceCredentialReader(log logging.Logger) ServiceCredentialReader {
	return mustNewClient(log)
}

func MustNewCredentailAdmin(log logging.Logger) ServiceCredentialAdmin {
	return mustNewClient(log)
}

func (c *client) getServiceSecretPath(userName string, serviceType string) string {
	return fmt.Sprintf("%s/%s/%s", c.conf.ServiceSecretPath, serviceType, userName)
}

func (c *client) GetServiceCredential(ctx context.Context, userName string, serviceType string) (cred ServiceCredentail, err error) {
	cred = ServiceCredentail{}
	secretPath := c.getServiceSecretPath(userName, serviceType)
	credentialDataBytes, err := c.readFromSecretPath(secretPath)
	if err != nil {
		err = errors.WithMessagef(err, "error in reading service credential for [userName: %s, serviceType: %s]", userName, serviceType)
		return
	}

	err = json.Unmarshal(credentialDataBytes, &cred)
	if err != nil {
		err = errors.WithMessagef(err, "error in unmarshalling service credential for [userName: %s, serviceType: %s]", userName, serviceType)
	}
	return
}

func (c *client) PutServiceCredential(ctx context.Context, userName string, serviceType string, cred ServiceCredentail) (err error) {
	credBytes, _ := json.Marshal(&cred)
	credMapData := make(map[string]interface{})
	credMapData[serviceCredentailDatakey] = string(credBytes)

	secretPath := c.getServiceSecretPath(userName, serviceType)
	_, err = c.vc.Logical().Write(secretPath, credMapData)
	if err != nil {
		err = errors.WithMessagef(err, "error in writing service credential for [userName: %s, serviceType: %s]", userName, serviceType)
	}
	return
}

func (c *client) DeleteServiceCredential(ctx context.Context, userName string, serviceType string) (err error) {
	secretPath := c.getServiceSecretPath(userName, serviceType)
	_, err = c.vc.Logical().Delete(secretPath)
	if err != nil {
		err = errors.WithMessagef(err, "error in deleting service credential for [userName: %s, serviceType: %s]", userName, serviceType)
	}
	return
}

func (c *client) readFromSecretPath(secretPath string) ([]byte, error) {
	secretValByPath, err := c.vc.Logical().Read(secretPath)
	if err != nil {
		return nil, errors.WithMessage(err, "error in reading vault secret")
	}

	if secretValByPath == nil {
		return nil, errors.WithMessage(err, "secret not found")
	}

	var secretDataValues = make(map[string][]byte)
	for key, value := range secretValByPath.Data {
		if value != nil {
			secretDataValues[key] = []byte(value.(string))
		} else {
			return nil, errors.WithMessage(err, "secret data is corrupted")
		}
	}
	return secretDataValues[serviceCredentailDatakey], nil
}
