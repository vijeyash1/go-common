package iam

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"context"

	cerbospb "github.com/intelops/go-common/iam/proto/cerbosproto"
	cmpb "github.com/intelops/go-common/iam/proto/iamproto"
	interceptorpb "github.com/intelops/go-common/iam/proto/interceptorproto"
	"google.golang.org/grpc/status"

	cerbos "github.com/cerbos/cerbos/client"
	"github.com/intelops/go-common/logging"
	ory "github.com/ory/client-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"gopkg.in/yaml.v2"
)

type Key string

const (
	authorizationHeader = "authorization"
	bearerTokenPrefix   = "Bearer"
)

type InterceptorConfig struct {
	Exclude               []string `yaml:"exclude"`
	Authenticate          []string `yaml:"authenticate"`
	AuthenticateAuthorize []string `yaml:"authenticate-authorize"`
}

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

type IamConnOptions func(*ClientsAndConfigs)

type IAMClient struct {
	IC          cmpb.CommonModuleClient
	CC          cerbospb.CerbosModuleServiceClient
	Interceptor interceptorpb.CommonInterceptorServiceClient
}

type ClientsAndConfigs struct {
	IAMClient           *IAMClient
	GrpcDialOpts        []grpc.DialOption
	IamYamlPath         string
	CerbosYamlPath      string
	Logger              logging.Logger
	InterceptorYamlPath string
	OryUrl              *string
	OryPat              *string
	OryClient           *ory.APIClient
	Scope               *string
	CerbosUrl           *string
	CerbosUsername      *string
	CerbosPassword      *string
	CerbosClient        cerbos.Client
}

func (iamConn *ClientsAndConfigs) InitializeOrySdk() error {
	if iamConn.OryUrl == nil {
		return errors.New(`please add ory Url and OryPat using
		Func WithOryCreds(oryUrl, oryPat string) before
		calling InitializeCerbosSdk() for More info refer
		the provided example in
		https://github.com/intelops/go-common/blob/main/examples/iam/iam.go`)
	}
	orySdkClient := iamConn.newOrySdk(*iamConn.OryUrl)
	if orySdkClient == nil {
		return errors.New("ory client creation failed and its nil")
	}
	iamConn.OryClient = orySdkClient
	return nil
}
func WithCerbosCreds(cerbosUrl, cerbosUsername, cerbosPassword string) IamConnOptions {
	return func(iamConn *ClientsAndConfigs) {
		iamConn.CerbosUrl = &cerbosUrl
		iamConn.CerbosUsername = &cerbosUsername
		iamConn.CerbosPassword = &cerbosPassword
	}
}
func (iamConn *ClientsAndConfigs) IntializeCerbosSdk() error {
	if iamConn.CerbosUrl == nil {
		return errors.New(`please add CerbosUrl,CerbosUsername and CerbosPassword using
		Func WithCerbosCreds(cerbosUrl, cerbosUsername, cerbosPassword string) before
		calling InitializeCerbosSdk() for More info refer
		the provided example in
		https://github.com/intelops/go-common/blob/main/examples/iam/iam.go`)
	}
	cli, err := cerbos.New(*iamConn.CerbosUrl, cerbos.WithPlaintext())
	if err != nil {
		return errors.New(fmt.Sprintf("unable to create cerbos client %v", err))
	}
	iamConn.CerbosClient = cli
	return nil
}
func newIAMClient(iamaddress string, opts ...grpc.DialOption) (*IAMClient, error) {
	conn, err := grpc.Dial(iamaddress, opts...)
	if err != nil {
		return nil, err
	}
	client := cmpb.NewCommonModuleClient(conn)
	cerbosclient := cerbospb.NewCerbosModuleServiceClient(conn)
	interceptorclient := interceptorpb.NewCommonInterceptorServiceClient(conn)
	return &IAMClient{
		IC:          client,
		CC:          cerbosclient,
		Interceptor: interceptorclient,
	}, nil
}

func WithIamAddress(iamaddress string) IamConnOptions {
	return func(iamConn *ClientsAndConfigs) {
		client, err := newIAMClient(iamaddress, iamConn.GrpcDialOpts...)
		if err != nil {
			iamConn.Logger.Fatalf("Error creating IAM client: %v", err)
		}
		iamConn.IAMClient = client
	}
}
func WithInterceptorYamlPath(path string) IamConnOptions {
	return func(iamconn *ClientsAndConfigs) {
		iamconn.InterceptorYamlPath = path
	}
}
func NewIamConn(opts ...IamConnOptions) *ClientsAndConfigs {
	logger := logging.NewLogger()
	iamConn := &ClientsAndConfigs{
		Logger: logger,
	}
	for _, opt := range opts {
		opt(iamConn)
	}
	return iamConn
}
func WithOryCreds(oryUrl, oryPat string) IamConnOptions {
	return func(iamconn *ClientsAndConfigs) {
		iamconn.OryUrl = &oryUrl
		iamconn.OryPat = &oryPat
	}
}
func WithGrpcDialOption(grpcOpts ...grpc.DialOption) IamConnOptions {
	return func(iamConn *ClientsAndConfigs) {
		iamConn.GrpcDialOpts = grpcOpts
	}
}

func WithIamYamlPath(path string) IamConnOptions {
	return func(iamConn *ClientsAndConfigs) {
		iamConn.IamYamlPath = path
	}
}
func WithScope(scope string) IamConnOptions {
	return func(iamConn *ClientsAndConfigs) {
		iamConn.Scope = &scope
	}
}
func WithCerbosYamlPath(path string) IamConnOptions {
	return func(iamConn *ClientsAndConfigs) {
		iamConn.CerbosYamlPath = path
	}
}
func (iamConn *ClientsAndConfigs) verifyVersion() (string, bool, error) {
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

func (iamConn *ClientsAndConfigs) readConfig(config *ActionRolePayload) error {
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

func (iamConn *ClientsAndConfigs) readCerbosConfig(config *Policies) error {
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

func (iamConn *ClientsAndConfigs) UpdateActionRoles(ctx context.Context) error {
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

	oauthTokens, ok := md["oauth_token"]
	if !ok {
		return errors.New("oauth_token not found in metadata")
	}

	if iamConn.OryPat == nil {
		return errors.New(`please add ory Url and OryPat using
		Func WithOryCreds(oryUrl, oryPat string) before
		calling UpdateActionRoles() for More info refer
		the provided example in
		https://github.com/intelops/go-common/blob/main/examples/iam/iam.go`)
	}
	oryAuthedContext := context.WithValue(ctx, ory.ContextAccessToken, *iamConn.OryPat)
	// Introspect the OAuth token to get the ClientId
	introspectionResponse, _, err := iamConn.OryClient.OAuth2Api.IntrospectOAuth2Token(oryAuthedContext).Token(oauthTokens[0]).Execute()
	if err != nil {
		return err
	}
	if introspectionResponse == nil || introspectionResponse.ClientId == nil {
		return errors.New("introspection response or client ID is nil")
	}
	clientId := *introspectionResponse.ClientId

	// Fetch the client details using the ClientId
	clientDetails, _, err := iamConn.OryClient.OAuth2Api.GetOAuth2Client(oryAuthedContext, clientId).Execute()
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

func (iamConn *ClientsAndConfigs) newOrySdk(oryURL string) *ory.APIClient {
	config := ory.NewConfiguration()
	config.Servers = ory.ServerConfigurations{{
		URL: oryURL,
	}}

	return ory.NewAPIClient(config)
}

func (iamConn *ClientsAndConfigs) RegisterCerbosResourcePolicies(ctx context.Context) error {
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
	oauthTokens, ok := md["oauth_token"]
	if !ok {
		return errors.New("oauth_token not found in metadata")
	}
	if iamConn.OryPat == nil {
		return errors.New(`please add ory Url and OryPat using
		Func WithOryCreds(oryUrl, oryPat string) before
		calling UpdateActionRoles() for More info refer
		the provided example in
		https://github.com/intelops/go-common/blob/main/examples/iam/iam.go`)
	}
	oryAuthedContext := context.WithValue(ctx, ory.ContextAccessToken, *iamConn.OryPat)
	introspectionResponse, _, err := iamConn.OryClient.OAuth2Api.IntrospectOAuth2Token(oryAuthedContext).Token(oauthTokens[0]).Execute()
	if err != nil {
		return err
	}
	if introspectionResponse == nil || introspectionResponse.ClientId == nil {
		return errors.New("introspection response or client ID is nil")
	}
	clientId := *introspectionResponse.ClientId

	clientDetails, _, err := iamConn.OryClient.OAuth2Api.GetOAuth2Client(oryAuthedContext, clientId).Execute()
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

func (iamConn *ClientsAndConfigs) authorize(ctx context.Context, accessToken string) (context.Context, error) {
	if iamConn.OryPat == nil {
		return ctx, errors.New(`please add ory Url and OryPat using
		Func WithOryCreds(oryUrl, oryPat string) before
		calling authorize() for More info refer
		the provided example in
		https://github.com/intelops/go-common/blob/main/examples/iam/iam.go`)
	}
	ctx = context.WithValue(ctx, ory.ContextAccessToken, *iamConn.OryPat)
	sessionInfo, _, err := iamConn.OryClient.IdentityApi.GetSession(ctx, accessToken).Expand([]string{"Identity"}).Execute()
	if err != nil {
		iamConn.Logger.Errorf("Error occurred while getting session info for session id: %s: %v", accessToken, err)
		return ctx, status.Errorf(codes.Unauthenticated, "Failed to introspect session id - %v", err)
	}
	iamConn.Logger.Infof("session: %s", sessionInfo.Id)
	if !sessionInfo.GetActive() {
		iamConn.Logger.Errorf("Error occurred while getting session info for session id: %s", accessToken)
		return ctx, status.Error(codes.Unauthenticated, "session id is not active")
	}
	ctx = context.WithValue(ctx, Key("SESSION_ID"), sessionInfo.Id)
	ctx = context.WithValue(ctx, Key("ORY_ID"), sessionInfo.GetIdentity().Id)
	return ctx, nil
}

func (iamConn *ClientsAndConfigs) getOrgIdFromContext(ctx context.Context) (*string, error) {
	md, err := iamConn.getMetadataFromContext(ctx)
	if err != nil {
		return nil, err
	}
	orgid := md.Get("organisationid")
	if len(orgid) == 0 {
		iamConn.Logger.Error("Missing 'organisationid' in the provided metadata context , This context should be provided from the frontfacing interface.")
		return nil, status.Error(codes.Unauthenticated, "Missing 'organisationid' in the provided metadata context, Consider adding 'organisationid'")
	}
	return &orgid[0], nil

}

func (iamConn *ClientsAndConfigs) getMetadataFromContext(ctx context.Context) (metadata.MD, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		iamConn.Logger.Error("Failed to get metadata from context")
		return nil, status.Error(codes.Unauthenticated, "Failed to get metadata from context")
	}
	return md, nil
}

func (iamConn *ClientsAndConfigs) getTokenFromContext(ctx context.Context) (string, error) {
	md, err := iamConn.getMetadataFromContext(ctx)
	if err != nil {
		return "", err
	}
	bearerToken := md.Get(authorizationHeader)
	if len(bearerToken) == 0 {
		iamConn.Logger.Error("No access token provided")
		return "", status.Error(codes.Unauthenticated, "No access token provided")
	}
	splitToken := strings.Split(bearerToken[0], " ")
	if len(splitToken) != 2 || splitToken[0] != bearerTokenPrefix {
		iamConn.Logger.Error("Invalid access token")
		return "", status.Error(codes.Unauthenticated, "Invalid access token")
	}
	return splitToken[1], nil
}

func (iamConn *ClientsAndConfigs) readInterceptorConfig(config *InterceptorConfig) error {
	fileLocation := iamConn.InterceptorYamlPath
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

func (iamConn *ClientsAndConfigs) UnaryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	iamConn.Logger.Info("func UnaryInterceptor invoked")
	iamConn.Logger.Infof("called the method:  %v", info.FullMethod)
	defer iamConn.Logger.Info("func UnaryInterceptor exited")

	config := &InterceptorConfig{}
	err := iamConn.readInterceptorConfig(config)
	if err != nil {
		iamConn.Logger.Errorf("Error occurred while reading config file: %v", err)
		st := status.New(codes.Internal, "Error occurred while reading config file")
		return nil, st.Err()
	}

	if contains(config.Exclude, info.FullMethod) {
		return handler(ctx, req)
	}
	if contains(config.Authenticate, info.FullMethod) {
		accessToken, err := iamConn.getTokenFromContext(ctx)
		if err != nil {
			iamConn.Logger.Errorf("Error occurred while getting session id from context: %v", err)
			st := status.New(codes.Unauthenticated, "Error occurred while getting session id from context")
			return nil, st.Err()
		}

		ctx, err = iamConn.authorize(ctx, accessToken)
		if err != nil {
			iamConn.Logger.Errorf("Error occurred while authorizing the session id from context: %s: %v", accessToken, err)
			st := status.New(codes.PermissionDenied, "Error occurred while authorizing the session id from context")
			return nil, st.Err()
		}

		return handler(ctx, req)
	}

	if contains(config.AuthenticateAuthorize, info.FullMethod) {
		// If the method is in the AuthenticateAuthorize list, check if the session is active and perform authorization logic
		accessToken, err := iamConn.getTokenFromContext(ctx)
		if err != nil {
			iamConn.Logger.Errorf("Error occurred while getting session id from context: %v", err)
			st := status.New(codes.Unauthenticated, "Error occurred while getting session id from context")
			return nil, st.Err()
		}

		ctx, err = iamConn.authorize(ctx, accessToken)
		if err != nil {
			iamConn.Logger.Errorf("Error occurred while authorizing the session id from context: %s: %v", accessToken, err)
			st := status.New(codes.PermissionDenied, "Error occurred while authorizing the session id from context")
			return nil, st.Err()
		}
		// Get the metadata from the incoming context
		oryid, err := iamConn.getOryIDFromContext(ctx)
		if err != nil {
			iamConn.Logger.Errorf("Error occurred while getting ory id from context: %v", err)
			st := status.New(codes.Internal, "Error occurred while getting ory id from context")
			return nil, st.Err()
		}

		orgid, err := iamConn.getOrgIdFromContext(ctx)
		if err != nil {
			iamConn.Logger.Errorf("Error occurred while getting org id from context: %v", err)
			st := status.New(codes.Internal, "Error occurred while getting org id from context")
			return nil, st.Err()
		}
		actionsResponse, err := iamConn.IAMClient.Interceptor.GetActionsWithOryidOrgid(ctx, &interceptorpb.GetActionsPayload{Oryid: oryid,
			Orgid: *orgid})
		if err != nil {
			st := status.New(codes.Internal, "Error occurred while getting actions associated with user in organization using IAM client")
			return nil, st.Err()
		}
		actions := actionsResponse.Actions
		principal := cerbos.NewPrincipal(actionsResponse.Email, "iam")
		input := strings.TrimPrefix(info.FullMethod, "/")
		input = strings.ReplaceAll(input, "/", "-")
		input = strings.ReplaceAll(input, ".", "-")
		if iamConn.Scope == nil {
			st := status.New(codes.Internal, `please add Scope using
			WithScope before
		using Interceptor for More info refer
		the provided example in
		https://github.com/intelops/go-common/blob/main/examples/iam/iam.go`)
			return nil, st.Err()
		}
		r := cerbos.NewResource(input, actionsResponse.Email).WithScope(*iamConn.Scope)
		allowed := false
		for _, action := range actions {
			allowed, err = iamConn.CerbosClient.IsAllowed(context.Background(), principal, r, action)
			if err != nil {
				iamConn.Logger.Info("Error occurred while checking is allowed or not. " +
					fmt.Sprintf("\nError - %s", err.Error()),
				)
				return nil, err
			}

			if allowed {
				break
			}
		}
		if allowed {
			return handler(ctx, req)
		} else {
			return nil, fmt.Errorf("not allowed")
		}
	}
	return handler(ctx, req)
}

func contains(slice []string, value string) bool {
	for _, item := range slice {
		if item == value {
			return true
		}
	}
	return false
}

func (iamConn *ClientsAndConfigs) getOryIDFromContext(ctx context.Context) (string, error) {
	oryID := ctx.Value(Key("ORY_ID"))
	if oryID == nil {
		return "", status.Error(codes.Unauthenticated, "Failed to get ory id from context")
	}
	return oryID.(string), nil
}
