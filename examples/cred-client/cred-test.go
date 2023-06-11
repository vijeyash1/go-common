package main

import (
	"context"
	"fmt"
	"os"

	vaultcredclient "github.com/intelops/go-common/vault-cred-client"
)

func main() {
	_ = os.Setenv("VAULT_CRED_SERVICE", "localhost:9098")
	_ = os.Setenv("VAULT_ROLE", "test-cred-reader")
	_ = os.Setenv("SERVICE_ACCOUNT_TOKEN_PATH", "./dummyToken")

	serviceCredExample()
	certificateCredExample()
}

func serviceCredExample() {

	userName := "user3"
	password := "pwd2"
	entity := "DB"

	svcAdmin, err := vaultcredclient.NewServiceCredentailAdmin()
	if err != nil {
		fmt.Printf("init %v\n", err)
		return
	}

	svcReadClient, err := vaultcredclient.NewServiceCredentailReader()
	if err != nil {
		fmt.Printf("init %v\n", err)
		return
	}

	err = svcAdmin.PutServiceCredential(context.Background(), entity, userName, vaultcredclient.ServiceCredentail{
		UserName: userName,
		Password: password,
	})
	if err != nil {
		fmt.Printf("put %v\n", err)
		return
	}

	svcCred, err := svcReadClient.GetServiceCredential(context.Background(), entity, userName)
	if err != nil {
		fmt.Printf("read error %v\n", err)
		return
	}
	if svcCred.UserName == userName && svcCred.Password == password {
		fmt.Printf("svc cred read correctly %v\n", svcCred)
	} else {
		fmt.Printf("svc cred not read correctly %v\n", svcCred)
	}

	err = svcAdmin.DeleteServiceCredential(context.Background(), entity, userName)
	if err != nil {
		fmt.Printf("delete %v\n", err)
		return
	}
	svcCred, err = svcReadClient.GetServiceCredential(context.Background(), entity, userName)
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}
	fmt.Printf("read after delete %v\n", svcCred)
}

func certificateCredExample() {
	certAdmin, err := vaultcredclient.NewCertificateAdmin()
	if err != nil {
		fmt.Printf("init %v\n", err)
		return
	}

	caCertData := "ca1"
	keyData := "key1"
	certData := "cert1"
	certIdentifier := "client-1"

	ctx := context.Background()
	err = certAdmin.StoreCertificate(ctx, vaultcredclient.CaptenClusterCert, certIdentifier,
		vaultcredclient.CertificateData{
			CACert: caCertData,
			Key:    keyData,
			Cert:   certData,
		})
	if err != nil {
		fmt.Printf("store failed %v\n", err)
		return
	}

	certReader, err := vaultcredclient.NewCertificateReader()
	if err != nil {
		fmt.Printf("init %v\n", err)
		return
	}

	readCertData, err := certReader.GetCertificate(ctx, vaultcredclient.CaptenClusterCert, certIdentifier)
	if err != nil {
		fmt.Printf("read failed %v\n", err)
		return
	}

	if readCertData.CACert == caCertData && readCertData.Key == keyData && readCertData.Cert == certData {
		fmt.Printf("cert read correctly %v\n", readCertData)
		return
	}
	fmt.Printf("cert not read correctly %v\n", readCertData)
}
