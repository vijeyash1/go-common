package iam

import (
	"errors"
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
	Category    string `yaml:"category"`
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
}

type IamConn struct {
	IAMClient    *IAMClient
	GrpcDialOpts []grpc.DialOption
	YamlPath     string
	Logger       logging.Logger
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

func (iamConn *IamConn) verifyVersion() (string, *ActionRolePayload, bool, bool, error) {
	config := &ActionRolePayload{}
	err := iamConn.readConfig(config)
	if err != nil {
		iamConn.Logger.Errorf("Error reading config file: %v", err)
		return "", nil, false, false, err
	}

	ctx := context.Background()
	resp, err := iamConn.IAMClient.IC.FetchServiceByName(ctx, &cmpb.FetchServiceByNameRequest{
		Name: config.ServiceName, // Use the ServiceName from the config
	})

	if err != nil {
		iamConn.Logger.Errorf("Error occurred while fetching service by name from IAMCLIENT: %v", err)
		return "", nil, false, false, err
	}

	var serviceID string
	var isNewService bool
	if resp == nil || resp.Id == "" {
		// Create a new service if it doesn't exist
		createResp, err := iamConn.IAMClient.IC.CreateServiceModule(ctx, &cmpb.CreateServiceRequest{
			ServiceName:        config.ServiceName,
			ServiceDescription: config.ServiceDescription, // Use the ServiceDescription from the config
		})
		if err != nil {
			iamConn.Logger.Errorf("Error occurred while creating service in IAMCLIENT: %v", err)
			return "", nil, false, false, err
		}
		serviceID = createResp.Id
		isNewService = true
		return serviceID, config, true, isNewService, nil
	} else {
		serviceID = resp.Id
	}

	IamVersion := resp.Version
	yamlVersion := config.Version
	if yamlVersion > IamVersion {
		return serviceID, config, true, isNewService, nil
	} else {
		return serviceID, config, false, isNewService, nil
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

func (iamConn *IamConn) UpdateActionRoles() error {
	serviceID, config, shouldUpdate, isNewService, err := iamConn.verifyVersion()
	if err != nil {
		return err
	}

	// Check for missing values in the YAML
	if config.ServiceName == "" {
		iamConn.Logger.Errorf("ServiceName is missing in the YAML")
		return errors.New("servicename is missing in the yaml")
	}
	if config.Version == 0 {
		iamConn.Logger.Errorf("Version is missing in the YAML")
		return errors.New("version is missing in the yaml")
	}
	if config.Actions == nil {
		iamConn.Logger.Errorf("Actions are missing in the YAML")
		return errors.New("actions are missing in the yaml")
	}

	ctx := context.Background()

	// Only register actions and roles if the service is newly created or if the YAML version is higher
	if isNewService || shouldUpdate {
		actionSlice := []*cmpb.ActionPayload{}
		RolesSlice := []*cmpb.RolePayload{}
		for _, action := range config.Actions {
			actionSlice = append(actionSlice, &cmpb.ActionPayload{
				Name:        action.Name,
				Displayname: action.DisplayName,
				Serviceid:   serviceID,
				Category:    action.Category,
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

		// Associate the correct actions with each role
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
			})
		}

		_, err = iamConn.IAMClient.IC.RegisterRoles(ctx, &cmpb.RegisterRolesRequest{
			Roles: RolesSlice,
		})
		if err != nil {
			return err
		}
	}

	if shouldUpdate && !isNewService {
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
	} else if !shouldUpdate && !isNewService {
		iamConn.Logger.Infof("Version is up to date with Iam server")
	}

	return nil
}
