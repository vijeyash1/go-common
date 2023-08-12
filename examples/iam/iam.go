package main

import (
	"log"

	cm "github.com/intelops/go-common/iam"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	// Set up gRPC connection options
	grpcOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}

	// Create an instance of IamConn with desired options
	// the order of calling the options should be same as given in example
	iamConn := cm.NewIamConn(
		cm.WithGrpcDialOption(grpcOpts...),
		cm.WithIamAddress("localhost:3001"),
		cm.WithServiceName("service1"),
		cm.WithIamYamlPath("provide the yaml location here"),
	)

	// Update action roles
	err := iamConn.UpdateActionRoles()
	if err != nil {
		log.Fatalf("Failed to update action roles: %v", err)
	}

}
