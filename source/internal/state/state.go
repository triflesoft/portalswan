package state

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/puzpuzpuz/xsync"
	"github.com/triflesoft/portalswan/internal/adapters/adapters"
	"github.com/triflesoft/portalswan/internal/adapters/aws_credentials_adapter"
	"github.com/triflesoft/portalswan/internal/adapters/aws_email_adapter"
	"github.com/triflesoft/portalswan/internal/adapters/aws_identity_adapter"
	"github.com/triflesoft/portalswan/internal/adapters/aws_logs_adapter"
	"github.com/triflesoft/portalswan/internal/settings"
)

type WorkerState struct {
	QuitChan    chan int
	AppState    *AppState
	initCounter atomic.Int32
}

type VpnConnectionState struct {
	Username              string
	ClientToServerBytes   atomic.Int64
	ServerToClientBytes   atomic.Int64
	ClientToServerPackets atomic.Int64
	ServerToClientPackets atomic.Int64
}

type AppState struct {
	LoggingAdapter     adapters.LoggingAdapter
	IdentityAdapter    adapters.IdentityAdapter
	CredentialsAdapter adapters.CredentialsAdapter
	EmailAdapter       adapters.EmailAdapter

	workerStates       []*WorkerState
	initGroup          *sync.WaitGroup
	quitGroup          *sync.WaitGroup
	appSettings        *settings.AppSettings
	connectionStateMap *xsync.MapOf[string, *VpnConnectionState]
	baseFileSystemPath string
}

func NewAppState() *AppState {
	appSettings := settings.NewAppSettings()
	exePath, err := os.Executable()

	if err != nil {
		fmt.Printf("error: %v\n", err)
		return nil
	}

	exePath, err = filepath.EvalSymlinks(exePath)

	if err != nil {
		fmt.Printf("error: %v\n", err)
		return nil
	}

	var loggingAdapter adapters.LoggingAdapter
	var identityAdapter adapters.IdentityAdapter
	var credentialsAdapter adapters.CredentialsAdapter
	var emailAdapter adapters.EmailAdapter

	if appSettings.Logging.Aws != nil {
		fmt.Printf("AWS Logging Adapter\n")
		fmt.Printf(" CloudWatch Logs\n")
		fmt.Printf("    Region Name:            '%s'\n", appSettings.Logging.Aws.CloudWatchLogRegion)
		fmt.Printf("    Group Name:             '%s'\n", appSettings.Logging.Aws.CloudWatchLogGroup)
		loggingAdapter = aws_logs_adapter.NewAwsLoggingAdapter(appSettings.Logging.Aws)
	} else {
		fmt.Printf("error: failed to configure logging adapter\n")
		return nil
	}

	if appSettings.Identity.Aws != nil {
		fmt.Printf("AWS Identity Provider\n")
		fmt.Printf(" IAM Identity Center\n")
		fmt.Printf("    Identity Store Region:  '%s'\n", appSettings.Identity.Aws.IdentityStoreRegion)
		fmt.Printf("    Identity Store Id:      '%s'\n", appSettings.Identity.Aws.IdentityStoreId)
		fmt.Printf("    Group Name Pattern:     '%s'\n", appSettings.Identity.Aws.RadiusClassFromGroupNamePattern)
		identityAdapter = aws_identity_adapter.NewAwsIdentityAdapter(appSettings.Identity.Aws, loggingAdapter)
	} else {
		fmt.Printf("error: failed to configure identity adapter\n")
		return nil
	}

	if appSettings.Credentials.Aws != nil {
		fmt.Printf("AWS Credentials Provider\n")
		fmt.Printf(" S3\n")
		fmt.Printf("    Bucket Region:          '%s'\n", appSettings.Credentials.Aws.S3BucketRegion)
		fmt.Printf("    Bucket Name:            '%s'\n", appSettings.Credentials.Aws.S3BucketName)
		credentialsAdapter = aws_credentials_adapter.NewAwsCredentialsAdapter(appSettings.Credentials.Aws, loggingAdapter)
	} else {
		fmt.Printf("error: failed to configure credentials adapter\n")
		return nil
	}

	if appSettings.Email.Aws != nil {
		fmt.Printf("AWS Email Provider\n")
		fmt.Printf(" SES\n")
		fmt.Printf("    Region:                 '%s'\n", appSettings.Email.Aws.SesRegion)
		fmt.Printf("    Source:                 '%s'\n", appSettings.Email.Aws.SesSource)
		emailAdapter = aws_email_adapter.NewAwsEmailAdapter(appSettings.Email.Aws, loggingAdapter)
	} else {
		fmt.Printf("error: failed to configure email adapter\n")
		return nil
	}

	fmt.Printf("Linux Process ID:           '%d'\n", os.Getpid())

	return &AppState{
		LoggingAdapter:     loggingAdapter,
		IdentityAdapter:    identityAdapter,
		CredentialsAdapter: credentialsAdapter,
		EmailAdapter:       emailAdapter,

		workerStates:       []*WorkerState{},
		initGroup:          &sync.WaitGroup{},
		quitGroup:          &sync.WaitGroup{},
		appSettings:        appSettings,
		connectionStateMap: xsync.NewTypedMapOf[string, *VpnConnectionState](xsync.StrHash64),
		baseFileSystemPath: filepath.Dir(exePath),
	}
}

func (appState *AppState) NewWorkerState() *WorkerState {
	appState.initGroup.Add(1)
	appState.quitGroup.Add(1)
	workerState := &WorkerState{
		QuitChan:    make(chan int),
		AppState:    appState,
		initCounter: atomic.Int32{},
	}

	appState.workerStates = append(appState.workerStates, workerState)

	return workerState
}

func (appState *AppState) WaitInitCompleted() {
	appState.initGroup.Wait()
}

func (appState *AppState) WaitQuitCompleted() {
	appState.quitGroup.Wait()
}

func (appState *AppState) Quit() {
	for _, workerState := range appState.workerStates {
		workerState.QuitChan <- 1
	}
}

func (appState *AppState) GetServerSettings() *settings.AppServerSettings {
	return appState.appSettings.Server
}

func (appState *AppState) GetClientSettings() *settings.AppClientSettings {
	return appState.appSettings.Client
}

func (appState *AppState) GetVpnConnectionState(framedIpAddress string) (*VpnConnectionState, bool) {
	return appState.connectionStateMap.Load(framedIpAddress)
}

func (appState *AppState) SetVpnConnectionState(framedIpAddress string, connectionState *VpnConnectionState) {
	appState.connectionStateMap.Store(framedIpAddress, connectionState)
}

func (appState *AppState) DelVpnConnectionState(framedIpAddress string) (*VpnConnectionState, bool) {
	return appState.connectionStateMap.LoadAndDelete(framedIpAddress)
}

func (appState *AppState) GetBaseFileSystemPath() string {
	return appState.baseFileSystemPath
}

func (workerState *WorkerState) ReportInitCompleted() {
	if workerState.initCounter.Add(1) == 1 {
		workerState.AppState.initGroup.Done()
	}
}

func (workerState *WorkerState) ReportQuitCompleted() {
	workerState.AppState.quitGroup.Done()
}
