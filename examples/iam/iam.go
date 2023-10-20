package main

import (
	"context"
	"log"

	cm "github.com/intelops/go-common/iam"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
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
		cm.WithIamYamlPath("provide the yaml location here"), // Ensure to provide the correct path to your YAML configuration
		cm.WithCerbosYamlPath("provide the cerbos yaml location here"),
		cm.WithOryCreds("oryUrl", "orypat_token"),
		cm.WithScope("scope is the service name"),
		cm.WithCerbosCreds("cerbosUrl", "cerbosUsername", "cerbosPassword"),
	)

	if err := iamConn.InitializeOrySdk(); err != nil {
		log.Fatalf("Failed to initialize Ory Sdk: %v", err)
	}
	if err := iamConn.IntializeCerbosSdk(); err != nil {
		log.Fatalf("Failed to initialize Cerbos Sdk: %v", err)
	}
	ctx := context.Background()
	md := metadata.Pairs("oauth_token", "dummytoken")
	newCtx := metadata.NewOutgoingContext(ctx, md)
	// Update action roles
	err := iamConn.UpdateActionRoles(newCtx)
	if err != nil {
		log.Fatalf("Failed to update action roles: %v", err)
	}
	err = iamConn.RegisterCerbosResourcePolicies(newCtx)
	if err != nil {
		log.Fatalf("Failed to Register cerbos Resource Policies: %v", err)
	}
}
