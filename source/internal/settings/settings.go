package settings

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/fernet/fernet-go"
)

type appIdentityAwsSettingsJson struct {
	IdentityStoreRegion             *string `json:"identity_store_region"`
	IdentityStoreId                 *string `json:"identity_store_id"`
	RadiusClassFromGroupNamePattern *string `json:"radius_class_from_group_name_pattern"`
}

type appIdentitySettingsJson struct {
	Aws *appIdentityAwsSettingsJson `json:"aws"`
}

type appCredentialsAwsSettingsJson struct {
	S3BucketRegion *string `json:"s3_bucket_region"`
	S3BucketName   *string `json:"s3_bucket_name"`
	FernetKeys     *string `json:"fernet_keys"`
}

type appCredentialsSettingsJson struct {
	Aws *appCredentialsAwsSettingsJson `json:"aws"`
}

type appEmailAwsSettingsJson struct {
	SesRegion *string `json:"ses_region"`
	SesSource *string `json:"ses_source"`
}

type appEmailSettingsJson struct {
	Aws *appEmailAwsSettingsJson `json:"aws"`
}

type appLoggingAwsSettingsJson struct {
	CloudWatchLogRegion *string `json:"cloudwatch_log_region"`
	CloudWatchLogGroup  *string `json:"cloudwatch_log_group"`
}

type appLoggingSettingsJson struct {
	Aws *appLoggingAwsSettingsJson `json:"aws"`
}

type appServerSettingsJson struct {
	TlsCertificatePath   *string `json:"tls_certificate_path"`
	TlsPrivateKeyPath    *string `json:"tls_private_key_path"`
	VerificationHostname *string `json:"verification_hostname"`
}

type appClientSettingsJson struct {
	DnsServers          *[]string `json:"dns_servers"`
	DnsSuffix           *string   `json:"dns_suffix"`
	DestinationPrefixes *[]string `json:"destination_prefixes"`
}

type appSettingsJson struct {
	Identity    *appIdentitySettingsJson    `json:"identity"`
	Credentials *appCredentialsSettingsJson `json:"credentials"`
	Email       *appEmailSettingsJson       `json:"email"`
	Logging     *appLoggingSettingsJson     `json:"logging"`
	Server      *appServerSettingsJson      `json:"server"`
	Client      *appClientSettingsJson      `json:"client"`
}

type AppCredentialsAwsSettings struct {
	S3BucketRegion string
	S3BucketName   string
	FernetKeys     []*fernet.Key
}

func (s *AppCredentialsAwsSettings) merge(sj *appCredentialsAwsSettingsJson) {
	if (sj.S3BucketRegion != nil) && (*sj.S3BucketRegion != "") &&
		(sj.S3BucketName != nil) && (*sj.S3BucketName != "") &&
		(sj.FernetKeys != nil) && (*sj.FernetKeys != "") {
		s.S3BucketRegion = *sj.S3BucketRegion
		s.S3BucketName = *sj.S3BucketName
		s.FernetKeys = fernet.MustDecodeKeys(*sj.FernetKeys)
	}
}

type AppCredentialsSettings struct {
	Aws *AppCredentialsAwsSettings
}

func (s *AppCredentialsSettings) merge(sj *appCredentialsSettingsJson) {
	if sj != nil {
		if (sj.Aws != nil) && (s.Aws == nil) {
			s.Aws = &AppCredentialsAwsSettings{}
		}

		s.Aws.merge(sj.Aws)
	}
}

type AppEmailAwsSettings struct {
	SesRegion string
	SesSource string
}

func (s *AppEmailAwsSettings) merge(sj *appEmailAwsSettingsJson) {
	if (sj.SesRegion != nil) && (*sj.SesRegion != "") &&
		(sj.SesSource != nil) && (*sj.SesSource != "") {
		s.SesRegion = *sj.SesRegion
		s.SesSource = *sj.SesSource
	}
}

type AppEmailSettings struct {
	Aws *AppEmailAwsSettings
}

func (s *AppEmailSettings) merge(sj *appEmailSettingsJson) {
	if sj != nil {
		if (sj.Aws != nil) && (s.Aws == nil) {
			s.Aws = &AppEmailAwsSettings{}
		}

		s.Aws.merge(sj.Aws)
	}
}

type AppIdentityAwsSettings struct {
	IdentityStoreRegion             string
	IdentityStoreId                 string
	RadiusClassFromGroupNamePattern string
}

func (s *AppIdentityAwsSettings) merge(sj *appIdentityAwsSettingsJson) {
	if (sj.IdentityStoreRegion != nil) && (*sj.IdentityStoreRegion != "") &&
		(sj.IdentityStoreId != nil) && (*sj.IdentityStoreId != "") &&
		(sj.RadiusClassFromGroupNamePattern != nil) && (*sj.RadiusClassFromGroupNamePattern != "") {
		s.IdentityStoreRegion = *sj.IdentityStoreRegion
		s.IdentityStoreId = *sj.IdentityStoreId
		s.RadiusClassFromGroupNamePattern = *sj.RadiusClassFromGroupNamePattern
	}
}

type AppIdentitySettings struct {
	Aws *AppIdentityAwsSettings
}

func (s *AppIdentitySettings) merge(sj *appIdentitySettingsJson) {
	if sj != nil {
		if (sj.Aws != nil) && (s.Aws == nil) {
			s.Aws = &AppIdentityAwsSettings{}
		}

		s.Aws.merge(sj.Aws)
	}
}

type AppLoggingAwsSettings struct {
	CloudWatchLogRegion string
	CloudWatchLogGroup  string
}

func (s *AppLoggingAwsSettings) merge(sj *appLoggingAwsSettingsJson) {
	if (sj.CloudWatchLogRegion != nil) && (*sj.CloudWatchLogRegion != "") &&
		(sj.CloudWatchLogGroup != nil) && (*sj.CloudWatchLogGroup != "") {
		s.CloudWatchLogRegion = *sj.CloudWatchLogRegion
		s.CloudWatchLogGroup = *sj.CloudWatchLogGroup
	}
}

type AppLoggingSettings struct {
	Aws *AppLoggingAwsSettings
}

func (s *AppLoggingSettings) merge(sj *appLoggingSettingsJson) {
	if sj != nil {
		if (sj.Aws != nil) && (s.Aws == nil) {
			s.Aws = &AppLoggingAwsSettings{}
		}

		s.Aws.merge(sj.Aws)
	}
}

type AppServerSettings struct {
	TlsCertificatePath   string
	TlsPrivateKeyPath    string
	VerificationHostname string
}

func (s *AppServerSettings) merge(sj *appServerSettingsJson) {
	if (sj.TlsCertificatePath != nil) && (*sj.TlsCertificatePath != "") &&
		(sj.TlsPrivateKeyPath != nil) && (*sj.TlsPrivateKeyPath != "") {
		s.TlsCertificatePath = *sj.TlsCertificatePath
		s.TlsPrivateKeyPath = *sj.TlsPrivateKeyPath
	}

	if (sj.VerificationHostname != nil) && (*sj.VerificationHostname != "") {
		s.VerificationHostname = *sj.VerificationHostname
	}
}

type AppClientSettings struct {
	DnsServers          []string
	DnsSuffix           string
	DestinationPrefixes []string
}

func (s *AppClientSettings) merge(sj *appClientSettingsJson) {
	contains := func(slice []string, item string) bool {
		for _, s := range slice {
			if s == item {
				return true
			}
		}
		return false
	}

	if sj.DnsServers != nil {
		if s.DnsServers == nil {
			s.DnsServers = make([]string, 0, 2)
		}

		for _, sjDnsServer := range *sj.DnsServers {
			if !(contains(s.DnsServers, sjDnsServer)) {
				s.DnsServers = append(s.DnsServers, sjDnsServer)
			}
		}
	}

	if (sj.DnsSuffix != nil) && (*sj.DnsSuffix != "") {
		s.DnsSuffix = *sj.DnsSuffix
	}

	if sj.DestinationPrefixes != nil {
		if s.DestinationPrefixes == nil {
			s.DestinationPrefixes = make([]string, 0, 2)
		}

		for _, sjDestinationPrefix := range *sj.DestinationPrefixes {
			if !(contains(s.DestinationPrefixes, sjDestinationPrefix)) {
				s.DestinationPrefixes = append(s.DestinationPrefixes, sjDestinationPrefix)
			}
		}
	}
}

type AppSettings struct {
	Identity    *AppIdentitySettings
	Credentials *AppCredentialsSettings
	Email       *AppEmailSettings
	Logging     *AppLoggingSettings
	Server      *AppServerSettings
	Client      *AppClientSettings
}

func (s *AppSettings) merge(sj *appSettingsJson) {
	if sj != nil {
		if sj.Identity != nil {
			if s.Identity == nil {
				s.Identity = &AppIdentitySettings{}
			}

			s.Identity.merge(sj.Identity)
		}

		if sj.Credentials != nil {
			if s.Credentials == nil {
				s.Credentials = &AppCredentialsSettings{}
			}

			s.Credentials.merge(sj.Credentials)
		}

		if sj.Email != nil {
			if s.Email == nil {
				s.Email = &AppEmailSettings{}
			}

			s.Email.merge(sj.Email)
		}

		if sj.Logging != nil {
			if s.Logging == nil {
				s.Logging = &AppLoggingSettings{}
			}

			s.Logging.merge(sj.Logging)
		}

		if sj.Server != nil {
			if s.Server == nil {
				hostname, _ := os.Hostname()

				s.Server = &AppServerSettings{
					VerificationHostname: hostname,
				}
			}

			s.Server.merge(sj.Server)
		}

		if sj.Client != nil {
			if s.Client == nil {
				s.Client = &AppClientSettings{}
			}

			s.Client.merge(sj.Client)
		}
	}
}

func (appSettings *AppSettings) updateFromFile(path string) {
	logger := slog.New(
		slog.NewJSONHandler(
			os.Stderr,
			&slog.HandlerOptions{AddSource: true, Level: slog.LevelDebug}))

	file, err := os.Open(path)

	if err != nil {
		logger.Error("Failed to open file", "err", err, "path", path)
		return
	}

	defer file.Close()

	appSettingsJson := &appSettingsJson{}

	if err := json.NewDecoder(file).Decode(appSettingsJson); err != nil {
		logger.Error("Failed to unmarshal JSON", "err", err)
		return
	}

	appSettings.merge(appSettingsJson)
}

func (appSettings *AppSettings) updateFromAws() {
	logger := slog.New(
		slog.NewJSONHandler(
			os.Stderr,
			&slog.HandlerOptions{AddSource: true, Level: slog.LevelDebug}))

	ctx := context.TODO()
	awsConfig, err := config.LoadDefaultConfig(ctx)

	if err != nil {
		logger.Error("Failed to load default AWS config", "err", err)
		return
	}

	imdsClient := imds.NewFromConfig(awsConfig)
	ec2InstanceIdOutput, err := imdsClient.GetMetadata(
		ctx,
		&imds.GetMetadataInput{
			Path: "instance-id",
		})

	if err != nil {
		logger.Error("Failed to get AWS EC2 instance metadata", "err", err)
		return
	}

	ec2InstanceIdData, _ := io.ReadAll(ec2InstanceIdOutput.Content)
	ec2InstanceId := string(ec2InstanceIdData)

	regionOutput, err := imdsClient.GetMetadata(
		ctx,
		&imds.GetMetadataInput{Path: "placement/region"})

	if err != nil {
		logger.Error("Failed to get AWS region metadata", "err", err)
		return
	}

	regionData, _ := io.ReadAll(regionOutput.Content)
	region := string(regionData)

	awsConfig.Region = region

	secretsClient := secretsmanager.NewFromConfig(awsConfig)
	secrets, err := secretsClient.GetSecretValue(
		ctx,
		&secretsmanager.GetSecretValueInput{SecretId: &ec2InstanceId})

	if err != nil {
		logger.Error("Failed to get secret value", "err", err, "secretId", ec2InstanceId)
		return
	}

	appSettingsJson := &appSettingsJson{}
	err = json.Unmarshal([]byte(*secrets.SecretString), appSettingsJson)

	if err != nil {
		logger.Error("Failed to unmarshal JSON", "err", err)
		return
	}

	appSettings.merge(appSettingsJson)
}

func NewAppSettings() *AppSettings {
	appSettings := &AppSettings{}

	appSettings.updateFromFile("/etc/portalswan/portalswan.conf")
	appSettings.updateFromAws()

	return appSettings
}
