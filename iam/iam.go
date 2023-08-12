package iam

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"context"

	cmpb "github.com/intelops/go-common/iam/proto"
	"github.com/intelops/go-common/logging"

	"google.golang.org/grpc"
	"gopkg.in/yaml.v2"
)

type Action struct {
	Name        string `yaml:"name"`
	DisplayName string `yaml:"displayname"`
}

type Role struct {
	Name        string   `yaml:"name"`
	DisplayName string   `yaml:"displayname"`
	Description string   `yaml:"description"`
	Owner       string   `yaml:"owner"`
	Actions     []string `yaml:"actions"`
}

type ActionRolePayload struct {
	Version   int32    `yaml:"version"`
	ServiceID string   `yaml:"serviceid"`
	Actions   []Action `yaml:"actions"`
	Roles     []Role   `yaml:"roles"`
}

type IamConnOptions func(*IamConn)

type IAMClient struct {
	IC cmpb.CommonModuleClient
}

type IamConn struct {
	IAMClient    *IAMClient
	GrpcDialOpts []grpc.DialOption
	YamlPath     string
	Logger       logging.Logger
	ServiceName  string
}

func newIAMClient(iamaddress string, opts ...grpc.DialOption) (*IAMClient, error) {
	conn, err := grpc.Dial(iamaddress, opts...)
	if err != nil {
		return nil, err
	}
	client := cmpb.NewCommonModuleClient(conn)
	return &IAMClient{
		IC: client,
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

func WithServiceName(serviceName string) IamConnOptions {
	return func(iamConn *IamConn) {
		iamConn.ServiceName = serviceName
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
		iamConn.YamlPath = path
	}
}

func (iamConn *IamConn) verifyVersion() (*ActionRolePayload, bool, error) {
	config := &ActionRolePayload{}
	err := iamConn.readConfig(config)
	if err != nil {
		iamConn.Logger.Errorf("Error reading config file: %v", err)
	}
	ctx := context.Background()
	resp, err := iamConn.IAMClient.IC.FetchServiceByName(ctx, &cmpb.FetchServiceByNameRequest{
		Name: iamConn.ServiceName,
	})
	if err != nil {
		iamConn.Logger.Errorf("Error occured while fetching service by name from IAMCLIENT: %v", err)
		return nil, false, err
	}
	IamVersion := resp.Version
	yamlVersion := config.Version
	if CompareVersion(IamVersion, yamlVersion) {
		return config, true, nil
	} else {
		return nil, false, nil
	}
}

func (iamConn *IamConn) readConfig(config *ActionRolePayload) error {
	// Read the file location from an environment variable
	fileLocation := iamConn.YamlPath
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

func CompareVersion(IamVersion, configVersion int32) bool {
	return configVersion > IamVersion
}

func (iamConn *IamConn) UpdateActionRoles() error {
	config, b, err := iamConn.verifyVersion()
	if err != nil {
		return err
	}
	if b {
		ctx := context.Background()
		actionSlice := []*cmpb.ActionPayload{}
		RolesSlice := []*cmpb.RolePayload{}
		for _, action := range config.Actions {
			actionSlice = append(actionSlice, &cmpb.ActionPayload{
				Name:        action.Name,
				Displayname: action.DisplayName,
				Serviceid:   config.ServiceID,
			})
		}
		actionsIds, err := iamConn.IAMClient.IC.RegisterActions(ctx, &cmpb.RegisterActionsRequest{
			Actions: actionSlice,
		})
		if err != nil {
			return err
		}

		// Create a map from action name to action ID
		actionNameToID := make(map[string]string)
		for i, action := range config.Actions {
			actionNameToID[action.Name] = actionsIds.Actionids[i].Actionid
		}
		an2s, _ := json.MarshalIndent(actionNameToID, "", "  ")
		fmt.Println("actionNameToID: ", string(an2s))
		// Associate the correct actions with each role
		for _, role := range config.Roles {
			roleActions := []string{}
			for _, actionName := range role.Actions {
				if actionID, ok := actionNameToID[actionName]; ok {
					roleActions = append(roleActions, actionID)
				}
			}
			fmt.Println("roleActions: ", roleActions)
			RolesSlice = append(RolesSlice, &cmpb.RolePayload{
				Rolename:    role.Name,
				Displayname: role.DisplayName,
				Owner:       role.Owner,
				Actionid:    roleActions,
				Serviceid:   config.ServiceID,
			})
			b, _ := json.MarshalIndent(RolesSlice, "", "  ")
			fmt.Println("RolesSlice: ", string(b))
		}

		_, err = iamConn.IAMClient.IC.RegisterRoles(ctx, &cmpb.RegisterRolesRequest{
			Roles: RolesSlice,
		})
		if err != nil {
			return err
		}
		res, err := iamConn.IAMClient.IC.UpdateServiceVersion(ctx, &cmpb.UpdateServiceVersionRequest{
			Servicename: iamConn.ServiceName,
			Version:     config.Version,
		})
		if err != nil {
			return err
		}
		if !res.Success {
			return errors.New("error updating version")
		}
	} else {
		iamConn.Logger.Infof("Version is up to date with Iam server")
	}
	return nil
}
