package vault

import (
	"context"
	"fmt"

	"github.com/pkg/errors"
)

const (
	clientCAFileKey   = "ca.pem"
	clientCertFileKey = "client.crt"
	clientKeyFileKey  = "client.key"
)

func (c *client) getCertSecretPath(clientID string) string {
	return fmt.Sprintf("cert-%s", clientID)
}

func (c *client) GetClientCertificateData(ctx context.Context, clientID string) (certData CertificateData, err error) {
	certData = CertificateData{}
	secretPath := c.getCertSecretPath(clientID)
	secretValByPath, err := c.vc.KVv2(c.conf.CertSecretPath).Get(context.Background(), secretPath)
	if err != nil {
		err = errors.WithMessagef(err, "error in reading certificate data for [clientID: %s]", clientID)
		return
	}

	if secretValByPath == nil {
		err = errors.WithMessagef(err, "certificate not found for [clientID: %s]", clientID)
		return
	}
	if secretValByPath.Data == nil {
		err = errors.WithMessagef(err, "certificate data is corrupted for [clientID: %s]", clientID)
		return
	}

	certData.CACert = secretValByPath.Data[clientCAFileKey].(string)
	certData.ClientCert = secretValByPath.Data[clientCertFileKey].(string)
	certData.ClientKey = secretValByPath.Data[clientKeyFileKey].(string)
	return
}

func (c *client) PutClientCertificateData(ctx context.Context, clientID string, certData CertificateData) (err error) {
	secretData := map[string]interface{}{
		clientCAFileKey:   certData.CACert,
		clientCertFileKey: certData.ClientCert,
		clientKeyFileKey:  certData.ClientKey,
	}

	secretPath := c.getCertSecretPath(clientID)
	_, err = c.vc.KVv2(c.conf.CertSecretPath).Put(ctx, secretPath, secretData)
	if err != nil {
		err = errors.WithMessagef(err, "error in writing certificate data for [clientID: %s]", clientID)
	}
	return
}

func (c *client) DeleteClientCertificateData(ctx context.Context, clientID string) (err error) {
	secretPath := c.getCertSecretPath(clientID)
	err = c.vc.KVv2(c.conf.CertSecretPath).Delete(ctx, secretPath)
	if err != nil {
		err = errors.WithMessagef(err, "error in deleting certificate data for [clientID: %s]", clientID)
	}
	return
}
