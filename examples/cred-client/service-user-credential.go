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

	err = svcAdmin.PutServiceCredential(context.Background(), "test", "db", vaultcredclient.ServiceCredentail{
		UserName: "venkat",
		Password: "reddy",
	})
	if err != nil {
		fmt.Printf("put %v\n", err)
		return
	}

	svcCred, err := svcReadClient.GetServiceCredential(context.Background(), "test", "db")
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}
	fmt.Printf("first-read %v\n", svcCred)

	err = svcAdmin.DeleteServiceCredential(context.Background(), "test", "db")
	if err != nil {
		fmt.Printf("delete %v\n", err)
		return
	}
	svcCred, err = svcReadClient.GetServiceCredential(context.Background(), "test", "db")
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}
	fmt.Printf("second-read %v\n", svcCred)
}
