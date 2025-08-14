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
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/fernet/fernet-go"
	"github.com/jellydator/ttlcache/v3"
	"github.com/triflesoft/portalswan/internal/adapters/adapters"
	"github.com/triflesoft/portalswan/internal/settings"
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
		a.log.LogErrorText(
			"Failed to get S3 object",
			"err", err,
			"s3BucketName", a.settings.S3BucketName,
			"objectKey", objectKey,
			"username", username)

		return nil
	}

	a.log.LogDebugText(
		"Got S3 object",
		"s3BucketName", a.settings.S3BucketName,
		"objectKey", objectKey,
		"username", username)

	objectData, err := io.ReadAll(objectOutput.Body)

	if err != nil {
		a.log.LogErrorText(
			"Failed to read S3 object body",
			"err", err,
			"s3BucketName", a.settings.S3BucketName,
			"objectKey", objectKey,
			"username", username)

		return nil
	}

	a.log.LogDebugText(
		"Read S3 object",
		"s3BucketName", a.settings.S3BucketName,
		"objectKey", objectKey,
		"username", username)

	credentials := vpnUserCredentials{}
	err = a.decryptJsonFromBytes(objectData, &credentials, 0)

	if err != nil {
		a.log.LogErrorText(
			"Failed to decrypt credentials",
			"err", err,
			"s3BucketName", a.settings.S3BucketName,
			"objectKey", objectKey,
			"username", username)

		return nil
	}

	a.log.LogDebugText(
		"Decrypted credentials",
		"s3BucketName", a.settings.S3BucketName,
		"objectKey", objectKey,
		"username", username)

	if credentials.NtPasswords == nil {
		credentials.NtPasswords = map[string]string{}
		a.log.LogDebugText(
			"Created new blank nt_passwords map, credentials were missing nt_passwords attribute",
			"s3BucketName", a.settings.S3BucketName,
			"objectKey", objectKey,
			"username", username)
	}

	if credentials.AccessTimes == nil {
		credentials.AccessTimes = map[string]int64{}
		a.log.LogDebugText(
			"Created new blank access_times map, credentials were missing access_times attribute",
			"s3BucketName", a.settings.S3BucketName,
			"objectKey", objectKey,
			"username", username)
	}

	expiresBefore := time.Now().Unix() - 15*24*60*60

	for ipAddress, accessTime := range credentials.AccessTimes {
		if accessTime < expiresBefore {
			delete(credentials.NtPasswords, ipAddress)
			a.log.LogDebugText(
				"Deleted expired NT password",
				"s3BucketName", a.settings.S3BucketName,
				"objectKey", objectKey,
				"username", username,
				"ipAddress", ipAddress,
				"accessTime", accessTime)
		}
	}

	type IpAddressAccessTime struct {
		IpAddress  string
		AccessTime int64
	}

	var ipAddressAccessTimes []IpAddressAccessTime

	for key, value := range credentials.AccessTimes {
		ipAddressAccessTimes = append(ipAddressAccessTimes, IpAddressAccessTime{key, value})
	}

	sort.Slice(ipAddressAccessTimes, func(i, j int) bool { return ipAddressAccessTimes[i].AccessTime > ipAddressAccessTimes[j].AccessTime })

	for i := 4; i < len(ipAddressAccessTimes); i++ {
		delete(credentials.NtPasswords, ipAddressAccessTimes[i].IpAddress)
		delete(credentials.AccessTimes, ipAddressAccessTimes[i].IpAddress)

		a.log.LogDebugText(
			"Deleted deprecated NT password",
			"s3BucketName", a.settings.S3BucketName,
			"objectKey", objectKey,
			"username", username,
			"ipAddress", ipAddressAccessTimes[i].IpAddress,
			"accessTime", ipAddressAccessTimes[i].AccessTime)
	}

	a.credentialsCache.Set(objectKey, &credentials, ttlcache.DefaultTTL)
	ipAddresses := make([]string, 0, len(credentials.NtPasswords))

	for ip_address := range credentials.NtPasswords {
		ipAddresses = append(ipAddresses, ip_address)
	}

	a.log.LogDebugText(
		"Got credentials",
		"s3BucketName", a.settings.S3BucketName,
		"objectKey", objectKey,
		"username", username,
		"ipAddresses", strings.Join(ipAddresses, ", "))

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
		a.log.LogErrorText(
			"Failed to encrypt credentials",
			"err", err,
			"s3BucketName", a.settings.S3BucketName,
			"objectKey", objectKey,
			"username", username)

		return err
	}

	a.log.LogDebugText(
		"Encrypted credentials",
		"s3BucketName", a.settings.S3BucketName,
		"objectKey", objectKey,
		"username", username)
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
		a.log.LogErrorText(
			"Failed to put S3 object",
			"err", err,
			"s3BucketName", a.settings.S3BucketName,
			"objectKey", objectKey,
			"username", username)

		return err
	}

	a.credentialsCache.Set(objectKey, credentials, ttlcache.DefaultTTL)
	a.log.LogDebugText(
		"Put S3 object",
		"err", err,
		"s3BucketName", a.settings.S3BucketName,
		"objectKey", objectKey,
		"username", username)
	ipAddresses := make([]string, 0, len(credentials.NtPasswords))

	for ip_address := range credentials.NtPasswords {
		ipAddresses = append(ipAddresses, ip_address)
	}

	a.log.LogDebugText(
		"Put credentials",
		"s3BucketName", a.settings.S3BucketName,
		"objectKey", objectKey,
		"username", username,
		"ipAddresses", strings.Join(ipAddresses, ", "))

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

	a.log.LogDebugText(
		"Selected IP addresses",
		"username", vpnUser.Username,
		"ipAddresses", strings.Join(ipAddresses, ", "))

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
		a.log.LogErrorText("Failed to get credentials, credentials are missing", "vpnUserUsername", vpnUser.Username)

		return ""
	}

	if credentials.Username != vpnUser.Username {
		a.log.LogErrorText(
			"Credentials username mismatch",
			"credentialsUsername", credentials.Username,
			"vpnUserUsername", vpnUser.Username)

		return ""
	}

	credentials.AccessTimes[ipAddress] = time.Now().Unix()

	a.putCredentials(ctx, s3Client, objectKey, vpnUser.Username, credentials)

	ntPassword, ok := credentials.NtPasswords[ipAddress]

	if ok {
		a.log.LogDebugText(
			"Selected NT password",
			"username", vpnUser.Username,
			"ipAddress", ipAddress)
	} else {
		a.log.LogErrorText(
			"Failed to select NT password",
			"username", vpnUser.Username,
			"ipAddress", ipAddress)
	}

	return ntPassword
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
			AccessTimes: map[string]int64{},
		}

		a.log.LogDebugText(
			"Created new blank credentials, credentials were missing",
			"vpnUserUsername", vpnUser.Username)
	}

	if credentials.Username != vpnUser.Username {
		a.log.LogErrorText(
			"Credentials username mismatch",
			"credentialsUsername", credentials.Username,
			"vpnUserUsername", vpnUser.Username)

		return
	}

	utf16le := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)
	utf16leEncoder := utf16le.NewEncoder()
	passwordUtf16Data, _, err := transform.String(utf16leEncoder, clearTextPassword)

	if err != nil {
		a.log.LogErrorText("Failed to encode NT password as UTF-16 little endian", "err", err)

		return
	}

	a.log.LogDebugText(
		"Encoded NT password as UTF-16 little endian",
		"vpnUserUsername", vpnUser.Username)

	hasher := md4.New()
	_, err = hasher.Write([]byte(passwordUtf16Data))

	if err != nil {
		a.log.LogErrorText("Failed to compute MD4 hash of NT password", "err", err)

		return
	}

	a.log.LogDebugText(
		"Computed MD4 hash of NT password",
		"vpnUserUsername", vpnUser.Username)

	credentials.NtPasswords[ipAddress] = strings.ToUpper(hex.EncodeToString(hasher.Sum(nil)))
	credentials.AccessTimes[ipAddress] = time.Now().Unix()

	err = a.putCredentials(ctx, s3Client, objectKey, vpnUser.Username, credentials)

	if err != nil {
		a.log.LogErrorText("Failed to update NT password", "err", err)

		return
	}

	a.log.LogDebugText(
		"Updated NT password",
		"username", vpnUser.Username,
		"ipAddress", ipAddress)
}

func NewAwsCredentialsAdapter(s *settings.AppCredentialsAwsSettings, l adapters.LoggingAdapter) *awsCredentialsAdapter {
	return &awsCredentialsAdapter{
		settings:         s,
		log:              l,
		credentialsCache: ttlcache.New(ttlcache.WithTTL[string, *vpnUserCredentials](15 * time.Second)),
	}
}
