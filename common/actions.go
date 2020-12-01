package common

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/httpclient"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/utils"
)

var (
	errUnconfiguredAction    = errors.New("no hook is configured for this action")
	errNoHook                = errors.New("unable to execute action, no hook defined")
	errUnexpectedHTTResponse = errors.New("unexpected HTTP response code")
)

// ProtocolActions defines the action to execute on file operations and SSH commands
type ProtocolActions struct {
	// Valid values are download, upload, pre-delete, delete, rename, ssh_cmd. Empty slice to disable
	ExecuteOn []string `json:"execute_on" mapstructure:"execute_on"`
	// Absolute path to an external program or an HTTP URL
	Hook string `json:"hook" mapstructure:"hook"`
}

var actionHandler ActionHandler = defaultActionHandler{}

// InitializeActionHandler lets the user choose an action handler implementation.
//
// Do NOT call this function after application initialization.
func InitializeActionHandler(handler ActionHandler) {
	actionHandler = handler
}

// SSHCommandActionNotification executes the defined action for the specified SSH command.
func SSHCommandActionNotification(user *dataprovider.User, filePath, target, sshCmd string, err error) {
	notification := newActionNotification(user, operationSSHCmd, filePath, target, sshCmd, ProtocolSSH, 0, err)

	go actionHandler.Handle(notification) // nolint:errcheck
}

// ActionHandler handles a notification for a Protocol Action.
type ActionHandler interface {
	Handle(notification ActionNotification) error
}

// ActionNotification defines a notification for a Protocol Action.
type ActionNotification struct {
	Action     string `json:"action"`
	Username   string `json:"username"`
	Path       string `json:"path"`
	TargetPath string `json:"target_path,omitempty"`
	SSHCmd     string `json:"ssh_cmd,omitempty"`
	FileSize   int64  `json:"file_size,omitempty"`
	FsProvider int    `json:"fs_provider"`
	Bucket     string `json:"bucket,omitempty"`
	Endpoint   string `json:"endpoint,omitempty"`
	Status     int    `json:"status"`
	Protocol   string `json:"protocol"`
}

func newActionNotification(
	user *dataprovider.User,
	operation, filePath, target, sshCmd, protocol string,
	fileSize int64,
	err error,
) ActionNotification {
	var bucket, endpoint string
	status := 1

	if err == ErrQuotaExceeded {
		status = 2
	} else if err != nil {
		status = 0
	}

	return ActionNotification{
		Action:     operation,
		Username:   user.Username,
		Path:       filePath,
		TargetPath: target,
		SSHCmd:     sshCmd,
		FileSize:   fileSize,
		FsProvider: int(user.FsConfig.Provider),
		Bucket:     bucket,
		Endpoint:   endpoint,
		Status:     status,
		Protocol:   protocol,
	}
}

type defaultActionHandler struct{}

func (h defaultActionHandler) Handle(notification ActionNotification) error {
	if !utils.IsStringInSlice(notification.Action, Config.Actions.ExecuteOn) {
		return errUnconfiguredAction
	}

	if Config.Actions.Hook == "" {
		logger.Warn(notification.Protocol, "", "Unable to send notification, no hook is defined")

		return errNoHook
	}

	if strings.HasPrefix(Config.Actions.Hook, "http") {
		return h.handleHTTP(notification)
	}

	return h.handleCommand(notification)
}

func (h defaultActionHandler) handleHTTP(notification ActionNotification) error {
	u, err := url.Parse(Config.Actions.Hook)
	if err != nil {
		logger.Warn(notification.Protocol, "", "Invalid hook %#v for operation %#v: %v", Config.Actions.Hook, notification.Action, err)

		return err
	}

	startTime := time.Now()
	respCode := 0

	httpClient := httpclient.GetHTTPClient()

	var b bytes.Buffer
	_ = json.NewEncoder(&b).Encode(notification)

	resp, err := httpClient.Post(u.String(), "application/json", &b)
	if err == nil {
		respCode = resp.StatusCode
		resp.Body.Close()

		if respCode != http.StatusOK {
			err = errUnexpectedHTTResponse
		}
	}

	logger.Debug(notification.Protocol, "", "notified operation %#v to URL: %v status code: %v, elapsed: %v err: %v", notification.Action, u.String(), respCode, time.Since(startTime), err)

	return err
}

func (h defaultActionHandler) handleCommand(notification ActionNotification) error {
	if !filepath.IsAbs(Config.Actions.Hook) {
		err := fmt.Errorf("invalid notification command %#v", Config.Actions.Hook)
		logger.Warn(notification.Protocol, "", "unable to execute notification command: %v", err)

		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, Config.Actions.Hook, notification.Action, notification.Username, notification.Path, notification.TargetPath, notification.SSHCmd)
	cmd.Env = append(os.Environ(), notificationAsEnvVars(notification)...)

	startTime := time.Now()
	err := cmd.Run()

	logger.Debug(notification.Protocol, "", "executed command %#v with arguments: %#v, %#v, %#v, %#v, %#v, elapsed: %v, error: %v",
		Config.Actions.Hook, notification.Action, notification.Username, notification.Path, notification.TargetPath, notification.SSHCmd, time.Since(startTime), err)

	return err
}

func notificationAsEnvVars(notification ActionNotification) []string {
	return []string{
		fmt.Sprintf("SFTPGO_ACTION=%v", notification.Action),
		fmt.Sprintf("SFTPGO_ACTION_USERNAME=%v", notification.Username),
		fmt.Sprintf("SFTPGO_ACTION_PATH=%v", notification.Path),
		fmt.Sprintf("SFTPGO_ACTION_TARGET=%v", notification.TargetPath),
		fmt.Sprintf("SFTPGO_ACTION_SSH_CMD=%v", notification.SSHCmd),
		fmt.Sprintf("SFTPGO_ACTION_FILE_SIZE=%v", notification.FileSize),
		fmt.Sprintf("SFTPGO_ACTION_FS_PROVIDER=%v", notification.FsProvider),
		fmt.Sprintf("SFTPGO_ACTION_BUCKET=%v", notification.Bucket),
		fmt.Sprintf("SFTPGO_ACTION_ENDPOINT=%v", notification.Endpoint),
		fmt.Sprintf("SFTPGO_ACTION_STATUS=%v", notification.Status),
		fmt.Sprintf("SFTPGO_ACTION_PROTOCOL=%v", notification.Protocol),
	}
}
