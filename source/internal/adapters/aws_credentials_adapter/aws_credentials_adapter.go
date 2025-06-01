package aws_credentials_adapter

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"portalswan/internal/adapters/adapters"
	"portalswan/internal/settings"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/fernet/fernet-go"
	"github.com/jellydator/ttlcache/v3"
	"golang.org/x/crypto/md4"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

type awsCredentialsAdapter struct {
	settings         *settings.AppCredentialsAwsSettings
	log              adapters.LoggingAdapter
	credentialsCache *ttlcache.Cache[string, *vpnUserCredentials]
}

type vpnUserCredentials struct {
	Username    string            `json:"username"`
	NtPasswords map[string]string `json:"nt_passwords"`
	AccessTimes map[string]int64  `json:"access_times"`
}

func (a *awsCredentialsAdapter) encryptJsonToBytes(cleartext any) ([]byte, error) {
	cleartextData, err := json.Marshal(cleartext)

	if err != nil {
		a.log.LogErrorText("Failed to marshal JSON", "err", err)
		return nil, err
	}

	return fernet.EncryptAndSign(cleartextData, a.settings.FernetKeys[0])
}

func (a *awsCredentialsAdapter) decryptJsonFromBytes(encryptedData []byte, cleartext any, ttl time.Duration) error {
	cleartextData := fernet.VerifyAndDecrypt(encryptedData, ttl, a.settings.FernetKeys)

	if cleartextData == nil {
		a.log.LogErrorText("Failed to decrypt fernet data")

		return errors.New("failed to decrypt fernet data")
	}

	return json.Unmarshal(cleartextData, cleartext)
}

func (a *awsCredentialsAdapter) getCredentials(ctx context.Context, s3Client *s3.Client, objectKey string, username string) *vpnUserCredentials {
	credentialsCacheItem := a.credentialsCache.Get(objectKey)

	if credentialsCacheItem != nil {
		return credentialsCacheItem.Value()
	}

	objectOutput, err := s3Client.GetObject(
		ctx,
		&s3.GetObjectInput{
			Bucket: &a.settings.S3BucketName,
			Key:    &objectKey,
		})

	if err != nil {
		a.log.LogErrorText("Failed to get S3 object", "err", err, "s3BucketName", a.settings.S3BucketName, "objectKey", objectKey, "username", username)

		return nil
	}

	objectData, err := io.ReadAll(objectOutput.Body)

	if err != nil {
		a.log.LogErrorText("Failed to read S3 object body", "err", err, "s3BucketName", a.settings.S3BucketName, "objectKey", objectKey, "username", username)

		return nil
	}

	credentials := vpnUserCredentials{}

	err = a.decryptJsonFromBytes(objectData, &credentials, 0)

	if err != nil {
		a.log.LogErrorText("Failed to decrypt credentials", "err", err, "s3BucketName", a.settings.S3BucketName, "objectKey", objectKey, "username", username)

		return nil
	}

	if credentials.AccessTimes == nil {
		credentials.AccessTimes = map[string]int64{}
	}

	expiresBefore := time.Now().Unix() - 15*24*60*60

	for ipAddress, accessTime := range credentials.AccessTimes {
		if accessTime < expiresBefore {
			a.log.LogDebugText("Delete expired NT password", "s3BucketName", a.settings.S3BucketName, "objectKey", objectKey, "username", username, "ipAddress", ipAddress, "accessTime", accessTime)
			delete(credentials.NtPasswords, ipAddress)
		}
	}

	a.credentialsCache.Set(objectKey, &credentials, ttlcache.DefaultTTL)

	return &credentials
}

func (a *awsCredentialsAdapter) putCredentials(ctx context.Context, s3Client *s3.Client, objectKey string, username string, credentials *vpnUserCredentials) error {
	for key := range credentials.AccessTimes {
		if _, exists := credentials.NtPasswords[key]; !exists {
			delete(credentials.AccessTimes, key)
		}
	}

	objectData, err := a.encryptJsonToBytes(credentials)

	if err != nil {
		a.log.LogErrorText("Failed to encrypt credentials", "err", err, "s3BucketName", a.settings.S3BucketName, "objectKey", objectKey, "username", username)

		return err
	}

	objectTags := url.Values{}
	objectTags.Add("Username", credentials.Username)

	for ipAddress, accessTime := range credentials.AccessTimes {
		objectTags.Add(ipAddress, fmt.Sprintf("%d", accessTime))
	}

	encodedObjectTags := objectTags.Encode()

	_, err = s3Client.PutObject(
		ctx,
		&s3.PutObjectInput{
			Bucket:  &a.settings.S3BucketName,
			Key:     &objectKey,
			Body:    bytes.NewReader(objectData),
			Tagging: &encodedObjectTags,
		})

	if err != nil {
		a.log.LogErrorText("Failed to put S3 object", "err", err, "s3BucketName", a.settings.S3BucketName, "objectKey", objectKey, "username", username)

		return err
	}

	a.credentialsCache.Set(objectKey, credentials, ttlcache.DefaultTTL)

	return nil
}

func (a *awsCredentialsAdapter) SelectIpAddresses(vpnUser *adapters.VpnUser) []string {
	ctx := context.TODO()
	awsConfig, err := config.LoadDefaultConfig(ctx, config.WithRegion(a.settings.S3BucketRegion))

	if err != nil {
		a.log.LogErrorText("Failed to load default AWS config", "err", err)

		return []string{}
	}

	s3Client := s3.NewFromConfig(awsConfig)
	userhash := sha512.Sum512([]byte(vpnUser.Username))
	objectKey := fmt.Sprintf("%s.bin", hex.EncodeToString(userhash[:]))
	credentials := a.getCredentials(ctx, s3Client, objectKey, vpnUser.Username)

	if credentials == nil {
		return []string{}
	}

	ipAddresses := make([]string, 0, len(credentials.NtPasswords))

	for ipAddress := range credentials.NtPasswords {
		ipAddresses = append(ipAddresses, ipAddress)
	}

	a.log.LogDebugText("SelectIpAddresses", "username", vpnUser.Username)

	return ipAddresses
}

func (a *awsCredentialsAdapter) SelectNtPassword(vpnUser *adapters.VpnUser, ipAddress string) string {
	ctx := context.TODO()
	awsConfig, err := config.LoadDefaultConfig(ctx, config.WithRegion(a.settings.S3BucketRegion))

	if err != nil {
		a.log.LogErrorText("Failed to load default AWS config", "err", err)
		return ""
	}

	s3Client := s3.NewFromConfig(awsConfig)
	userhash := sha512.Sum512([]byte(vpnUser.Username))
	objectKey := fmt.Sprintf("%s.bin", hex.EncodeToString(userhash[:]))
	credentials := a.getCredentials(ctx, s3Client, objectKey, vpnUser.Username)

	if credentials == nil {
		return ""
	}

	if credentials.Username != vpnUser.Username {
		a.log.LogErrorText("Username mismatch", "credentialsUsername", credentials.Username, "vpnUserUsername", vpnUser.Username)

		return ""
	}

	a.log.LogDebugText("SelectNtPassword", "username", vpnUser.Username, "ipAddress", ipAddress)

	credentials.AccessTimes[ipAddress] = time.Now().Unix()

	a.putCredentials(ctx, s3Client, objectKey, vpnUser.Username, credentials)

	return credentials.NtPasswords[ipAddress]
}

func (a *awsCredentialsAdapter) UpdateNtPassword(vpnUser *adapters.VpnUser, ipAddress string, clearTextPassword string) {
	ctx := context.TODO()
	awsConfig, err := config.LoadDefaultConfig(ctx, config.WithRegion(a.settings.S3BucketRegion))

	if err != nil {
		a.log.LogErrorText("Failed to load default AWS config", "err", err)
		return
	}

	s3Client := s3.NewFromConfig(awsConfig)
	userhash := sha512.Sum512([]byte(vpnUser.Username))
	objectKey := fmt.Sprintf("%s.bin", hex.EncodeToString(userhash[:]))
	credentials := a.getCredentials(ctx, s3Client, objectKey, vpnUser.Username)

	if credentials == nil {
		credentials = &vpnUserCredentials{
			Username:    vpnUser.Username,
			NtPasswords: map[string]string{},
		}
	}

	if credentials.Username != vpnUser.Username {
		a.log.LogErrorText("Username mismatch", "credentialsUsername", credentials.Username, "vpnUserUsername", vpnUser.Username)

		return
	}

	utf16le := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)
	utf16leEncoder := utf16le.NewEncoder()
	passwordUtf16Data, _, err := transform.String(utf16leEncoder, clearTextPassword)

	if err != nil {
		a.log.LogErrorText("Failed to encode NT password as UTF-16 little endian", "err", err)

		return
	}

	hasher := md4.New()
	_, err = hasher.Write([]byte(passwordUtf16Data))

	if err != nil {
		a.log.LogErrorText("Failed to compute MD4 hash of NT password", "err", err)

		return
	}

	credentials.NtPasswords[ipAddress] = strings.ToUpper(hex.EncodeToString(hasher.Sum(nil)))
	credentials.AccessTimes[ipAddress] = time.Now().Unix()

	if a.putCredentials(ctx, s3Client, objectKey, vpnUser.Username, credentials) == nil {
		a.log.LogDebugText("UpdateNtPassword", "username", vpnUser.Username, "ipAddress", ipAddress)
	}
}

func NewAwsCredentialsAdapter(s *settings.AppCredentialsAwsSettings, l adapters.LoggingAdapter) *awsCredentialsAdapter {
	return &awsCredentialsAdapter{
		settings:         s,
		log:              l,
		credentialsCache: ttlcache.New(ttlcache.WithTTL[string, *vpnUserCredentials](15 * time.Second)),
	}
}
