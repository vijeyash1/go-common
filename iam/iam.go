package iam

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"context"

	cerbospb "github.com/intelops/go-common/iam/proto/cerbosproto"
	cmpb "github.com/intelops/go-common/iam/proto/iamproto"
	"github.com/intelops/go-common/logging"

	ory "github.com/ory/client-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"gopkg.in/yaml.v2"
)

type CerbosResourcePolicy struct {
	ResourceName string   `yaml:"resourceName"`
	Actions      []string `yaml:"actions"`
}

type Policies struct {
	ServiceName string                 `yaml:"servicename"`
	Policies    []CerbosResourcePolicy `yaml:"policies"`
}

type Action struct {
	Name              string `yaml:"name"`
	DisplayName       string `yaml:"displayname"`
	ActionDescription string `yaml:"actiondescription"`
}

type Role struct {
	Name        string   `yaml:"name"`
	DisplayName string   `yaml:"displayname"`
	Description string   `yaml:"description"`
	Owner       string   `yaml:"owner"`
	Actions     []string `yaml:"actions"`
}

type ActionRolePayload struct {
	Version            int32    `yaml:"version"`
	ServiceName        string   `yaml:"servicename"`
	ServiceDescription string   `yaml:"servicedescription"`
	Actions            []Action `yaml:"actions"`
	Roles              []Role   `yaml:"roles"`
}

type IamConnOptions func(*IamConn)

type IAMClient struct {
	IC cmpb.CommonModuleClient
	CC cerbospb.CerbosModuleServiceClient
}

type IamConn struct {
	IAMClient      *IAMClient
	GrpcDialOpts   []grpc.DialOption
	IamYamlPath    string
	CerbosYamlPath string
	Logger         logging.Logger
}

func newIAMClient(iamaddress string, opts ...grpc.DialOption) (*IAMClient, error) {
	conn, err := grpc.Dial(iamaddress, opts...)
	if err != nil {
		return nil, err
	}
	client := cmpb.NewCommonModuleClient(conn)
	cerbosclient := cerbospb.NewCerbosModuleServiceClient(conn)
	return &IAMClient{
		IC: client,
		CC: cerbosclient,
	}, nil
}

func WithIamAddress(iamaddress string) IamConnOptions {
	return func(iamConn *IamConn) {
		client, err := newIAMClient(iamaddress, iamConn.GrpcDialOpts...)
		if err != nil {
			iamConn.Logger.Fatalf("Error creating IAM client: %v", err)
		}
		iamConn.IAMClient = client
	}
}

func NewIamConn(opts ...IamConnOptions) *IamConn {
	logger := logging.NewLogger()
	iamConn := &IamConn{
		Logger: logger,
	}
	for _, opt := range opts {
		opt(iamConn)
	}
	return iamConn
}

func WithGrpcDialOption(grpcOpts ...grpc.DialOption) IamConnOptions {
	return func(iamConn *IamConn) {
		iamConn.GrpcDialOpts = grpcOpts
	}
}

func WithIamYamlPath(path string) IamConnOptions {
	return func(iamConn *IamConn) {
		iamConn.IamYamlPath = path
	}
}
func WithCerbosYamlPath(path string) IamConnOptions {
	return func(iamConn *IamConn) {
		iamConn.CerbosYamlPath = path
	}
}
func (iamConn *IamConn) verifyVersion() (string, bool, error) {
	config := &ActionRolePayload{}
	err := iamConn.readConfig(config)
	if err != nil {
		iamConn.Logger.Errorf("Error reading config file: %v", err)
		return "", false, err
	}

	ctx := context.Background()
	resp, err := iamConn.IAMClient.IC.FetchServiceByName(ctx, &cmpb.FetchServiceByNameRequest{
		Name: config.ServiceName,
	})

	if err != nil {
		iamConn.Logger.Errorf("Error occurred while fetching service by name from IAMCLIENT: %v", err)
		return "", false, err
	}

	if resp == nil {
		iamConn.Logger.Errorf("Error occurred while fetching service by name from IAMCLIENT: %v", err)
		return "", false, errors.New("error occured while fetching service by name")
	}
	serviceID := resp.Id

	IamVersion := resp.Version
	yamlVersion := config.Version
	if yamlVersion > IamVersion {
		return serviceID, true, nil
	} else {
		return serviceID, false, nil
	}
}

func (iamConn *IamConn) readConfig(config *ActionRolePayload) error {
	// Read the file location from an environment variable
	fileLocation := iamConn.IamYamlPath
	if fileLocation == "" {
		fileLocation = "config.yaml"
	}
	// Open the file
	file, err := os.Open(fileLocation)
	if err != nil {
		return err
	}
	// Close the file when we are done
	defer file.Close()
	// Decode the file into our struct
	decoder := yaml.NewDecoder(file)
	err = decoder.Decode(config)
	if err != nil {
		return err
	}
	return nil
}

func (iamConn *IamConn) readCerbosConfig(config *Policies) error {
	fileLocation := iamConn.CerbosYamlPath
	if fileLocation == "" {
		return errors.New("file location for cerbos policy is not found")
	}
	file, err := os.Open(fileLocation)
	if err != nil {
		return err
	}
	defer file.Close()
	decoder := yaml.NewDecoder(file)
	err = decoder.Decode(config)
	if err != nil {
		return err
	}
	return nil
}

func (iamConn *IamConn) UpdateActionRoles(ctx context.Context) error {
	config := &ActionRolePayload{}
	err := iamConn.readConfig(config)
	if err != nil {
		iamConn.Logger.Errorf("Error reading config file: %v", err)
		return err
	}

	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		return errors.New("no metadata found in context")
	}

	// Extract specific metadata values
	oryURLs := md["ory_url"]
	oauthTokens := md["oauth_token"]
	oryPATs := md["ory_pat"]

	// Check if the values exist and assign them
	var oryURL, oauthToken, oryPAT string
	if len(oryURLs) > 0 {
		oryURL = oryURLs[0]
	} else {
		return errors.New("ory_url not found in metadata")
	}

	if len(oauthTokens) > 0 {
		oauthToken = oauthTokens[0]
	} else {
		return errors.New("oauth_token not found in metadata")
	}

	if len(oryPATs) > 0 {
		oryPAT = oryPATs[0]
	} else {
		return errors.New("ory_pat not found in metadata")
	}

	OryCli := iamConn.newOrySdk(oryURL)
	oryAuthedContext := context.WithValue(ctx, ory.ContextAccessToken, oryPAT)
	// Introspect the OAuth token to get the ClientId
	introspectionResponse, _, err := OryCli.OAuth2Api.IntrospectOAuth2Token(oryAuthedContext).Token(oauthToken).Execute()
	if err != nil {
		return err
	}
	if introspectionResponse == nil || introspectionResponse.ClientId == nil {
		return errors.New("introspection response or client ID is nil")
	}
	clientId := *introspectionResponse.ClientId

	// Fetch the client details using the ClientId
	clientDetails, _, err := OryCli.OAuth2Api.GetOAuth2Client(oryAuthedContext, clientId).Execute()
	if err != nil {
		return err
	}
	if clientDetails == nil || clientDetails.ClientName == nil {
		return errors.New("client details or client name is nil")
	}

	// Check for missing values in the YAML
	if config.ServiceName == "" {
		iamConn.Logger.Errorf("ServiceName is missing in the YAML")
		return errors.New("servicename is missing in the yaml")
	}
	// Compare the ClientName with the ServiceName in the config
	if !strings.EqualFold(*clientDetails.ClientName, config.ServiceName) {
		return errors.New("service name from token does not match service name in config")
	}
	if config.Version == 0 {
		iamConn.Logger.Errorf("Version is missing in the YAML")
		return errors.New("version is missing in the yaml")
	}
	if config.Actions == nil {
		iamConn.Logger.Errorf("Actions are missing in the YAML")
		return errors.New("actions are missing in the yaml")
	}
	serviceID, shouldUpdate, err := iamConn.verifyVersion()
	if err != nil {
		return err
	}
	if shouldUpdate {
		actionSlice := []*cmpb.ActionPayload{}
		RolesSlice := []*cmpb.RolePayload{}
		for _, action := range config.Actions {
			actionSlice = append(actionSlice, &cmpb.ActionPayload{
				Name:        action.Name,
				Displayname: action.DisplayName,
				Serviceid:   serviceID,
				Description: action.ActionDescription,
			})
		}
		actionsIds, err := iamConn.IAMClient.IC.RegisterActions(ctx, &cmpb.RegisterActionsRequest{
			Actions: actionSlice,
		})
		if err != nil {
			return err
		}
		actionNameToID := make(map[string]string)
		for i, action := range config.Actions {
			actionNameToID[action.Name] = actionsIds.Actionids[i].Actionid
		}
		for _, role := range config.Roles {
			roleActions := []string{}
			for _, actionName := range role.Actions {
				if actionID, ok := actionNameToID[actionName]; ok {
					roleActions = append(roleActions, actionID)
				}
			}
			RolesSlice = append(RolesSlice, &cmpb.RolePayload{
				Rolename:    role.Name,
				Displayname: role.DisplayName,
				Owner:       role.Owner,
				Actionid:    roleActions,
				Serviceid:   serviceID,
				Description: role.Description,
			})
		}

		_, err = iamConn.IAMClient.IC.RegisterRoles(ctx, &cmpb.RegisterRolesRequest{
			Roles: RolesSlice,
		})
		if err != nil {
			return err
		}
	}

	if shouldUpdate {
		res, err := iamConn.IAMClient.IC.UpdateServiceVersion(ctx, &cmpb.UpdateServiceVersionRequest{
			Servicename: config.ServiceName, // Use the ServiceName from the config
			Version:     config.Version,
		})
		if err != nil {
			return err
		}
		if !res.Success {
			return errors.New("error updating version")
		}
	} else if !shouldUpdate {
		iamConn.Logger.Infof("Version is up to date with Iam server")
	}

	return nil
}

func (iamConn *IamConn) newOrySdk(oryURL string) *ory.APIClient {
	config := ory.NewConfiguration()
	config.Servers = ory.ServerConfigurations{{
		URL: oryURL,
	}}

	return ory.NewAPIClient(config)
}

func (iamConn *IamConn) RegisterCerbosResourcePolicies(ctx context.Context) error {
	config := &Policies{}
	err := iamConn.readCerbosConfig(config)
	if err != nil {
		iamConn.Logger.Errorf("Error reading cerbos config file: %v", err)
		return err
	}
	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		return errors.New("no metadata found in context")
	}
	oryURLs := md["ory_url"]
	oauthTokens := md["oauth_token"]
	oryPATs := md["ory_pat"]
	var oryURL, oauthToken, oryPAT string
	if len(oryURLs) > 0 {
		oryURL = oryURLs[0]
	} else {
		return errors.New("ory_url not found in metadata")
	}

	if len(oauthTokens) > 0 {
		oauthToken = oauthTokens[0]
	} else {
		return errors.New("oauth_token not found in metadata")
	}

	if len(oryPATs) > 0 {
		oryPAT = oryPATs[0]
	} else {
		return errors.New("ory_pat not found in metadata")
	}
	OryCli := iamConn.newOrySdk(oryURL)
	oryAuthedContext := context.WithValue(ctx, ory.ContextAccessToken, oryPAT)
	introspectionResponse, _, err := OryCli.OAuth2Api.IntrospectOAuth2Token(oryAuthedContext).Token(oauthToken).Execute()
	if err != nil {
		return err
	}
	if introspectionResponse == nil || introspectionResponse.ClientId == nil {
		return errors.New("introspection response or client ID is nil")
	}
	clientId := *introspectionResponse.ClientId

	clientDetails, _, err := OryCli.OAuth2Api.GetOAuth2Client(oryAuthedContext, clientId).Execute()
	if err != nil {
		return err
	}
	if clientDetails == nil || clientDetails.ClientName == nil {
		return errors.New("client details or client name is nil")
	}
	if !strings.EqualFold(*clientDetails.ClientName, config.ServiceName) {
		return errors.New("service name from token does not match service name in config")
	}

	// New code
	// List current policies
	listReq := cerbospb.ListResourcePoliciesRequest{Servicename: config.ServiceName}
	listResp, err := iamConn.IAMClient.CC.ListResourcePolicies(ctx, &listReq)
	if err != nil {
		return fmt.Errorf("error listing current policies: %v", err)
	}
	currentPolicies := listResp.Policies

	// Create a map for easy lookup
	currentPolicyMap := make(map[string]struct{})
	for _, policy := range currentPolicies {
		currentPolicyMap[policy] = struct{}{}
	}

	// Register or update policies
	for _, policy := range config.Policies {
		addOrUpdateReq := cerbospb.AddOrUpdateResourcePolicyRequest{
			ResourceName: policy.ResourceName,
			Scope:        config.ServiceName,
			Actions:      policy.Actions,
		}
		_, err := iamConn.IAMClient.CC.AddOrUpdateResourcePolicy(ctx, &addOrUpdateReq)
		if err != nil {
			return fmt.Errorf("error registering or updating policy for resource %s: %v", policy.ResourceName, err)
		}
		delete(currentPolicyMap, "resource."+policy.ResourceName+".vdefault")
		delete(currentPolicyMap, "resource."+policy.ResourceName+".vdefault"+"/"+config.ServiceName)
	}

	for policy := range currentPolicyMap {
		disableReq := cerbospb.DisablePolicyRequest{Id: policy}
		_, err := iamConn.IAMClient.CC.DisablePolicy(ctx, &disableReq)
		if err != nil {
			return fmt.Errorf("error disabling policy %s: %v", policy, err)
		}
	}
	return nil
}
