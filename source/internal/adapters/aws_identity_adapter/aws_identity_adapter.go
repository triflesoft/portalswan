package aws_identity_adapter

import (
	"context"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/identitystore"
	identitystoreDocument "github.com/aws/aws-sdk-go-v2/service/identitystore/document"
	identitystoreTypes "github.com/aws/aws-sdk-go-v2/service/identitystore/types"
	ttlcache "github.com/jellydator/ttlcache/v3"
	"github.com/triflesoft/portalswan/internal/adapters/adapters"
	"github.com/triflesoft/portalswan/internal/settings"
)

type awsGroup struct {
	GroupId     string
	ExternalId  string
	DisplayName string
}

type awsUser struct {
	UserId      string
	ExternalId  string
	Username    string
	Email       string
	DisplayName string
}

type identitystoreClientFactory struct {
	Ctx      context.Context
	settings *settings.AppIdentityAwsSettings
	log      adapters.LoggingAdapter
	client   *identitystore.Client
	once     sync.Once
}

func (f *identitystoreClientFactory) GetIdentitystoreClient() *identitystore.Client {
	f.once.Do(
		func() {
			ctx := context.TODO()
			awsConfig, err := config.LoadDefaultConfig(ctx, config.WithRegion(f.settings.IdentityStoreRegion))

			if err != nil {
				f.log.LogErrorText("Failed to load default AWS config", "err", err)
				f.client = nil
			}

			f.client = identitystore.NewFromConfig(awsConfig)
		})
	return f.client
}

type awsIdentityAdapter struct {
	settings *settings.AppIdentityAwsSettings
	log      adapters.LoggingAdapter

	awsUserIdCache    *ttlcache.Cache[string, string]
	awsUserCache      *ttlcache.Cache[string, *awsUser]
	awsUserGroupCache *ttlcache.Cache[string, []string]
	awsGroupCache     *ttlcache.Cache[string, *awsGroup]
	vpnUserCache      *ttlcache.Cache[string, *adapters.VpnUser]
}

func (a *awsIdentityAdapter) selectAwsUserId(f *identitystoreClientFactory, username string) string {
	userIdCacheItem := a.awsUserIdCache.Get(username)

	if userIdCacheItem != nil {
		return userIdCacheItem.Value()
	}

	userIdOutput, err := f.GetIdentitystoreClient().GetUserId(
		f.Ctx,
		&identitystore.GetUserIdInput{
			IdentityStoreId: &a.settings.IdentityStoreId,
			AlternateIdentifier: &identitystoreTypes.AlternateIdentifierMemberUniqueAttribute{
				Value: identitystoreTypes.UniqueAttribute{
					AttributePath:  aws.String("emails.value"),
					AttributeValue: identitystoreDocument.NewLazyDocument(username),
				},
			},
		})

	if err != nil {
		a.log.LogErrorText("Failed to get AWS Identity Center user ID by username", "err", err, "username", username)

		return ""
	}

	return *userIdOutput.UserId
}

func (a *awsIdentityAdapter) selectAwsUser(f *identitystoreClientFactory, awsUserId string) *awsUser {
	userCacheItem := a.awsUserCache.Get(awsUserId)

	if userCacheItem != nil {
		return userCacheItem.Value()
	}

	describeUserOutput, err := f.GetIdentitystoreClient().DescribeUser(
		f.Ctx,
		&identitystore.DescribeUserInput{
			IdentityStoreId: &a.settings.IdentityStoreId,
			UserId:          &awsUserId,
		})

	if err != nil {
		a.log.LogErrorText("Failed to describe AWS Identity Center user", "err", err, "awsUserId", awsUserId)
		return nil
	}

	externalId := ""

	for _, value := range describeUserOutput.ExternalIds {
		if strings.HasPrefix(*value.Issuer, "https://scim.aws.com/") {
			externalId = *value.Id
		}
	}

	email := ""

	for _, value := range describeUserOutput.Emails {
		if value.Primary {
			email = *value.Value
		}
	}

	awsUser := &awsUser{
		UserId:      *describeUserOutput.UserId,
		ExternalId:  externalId,
		Username:    *describeUserOutput.UserName,
		Email:       email,
		DisplayName: *describeUserOutput.DisplayName,
	}

	a.awsUserCache.Set(awsUserId, awsUser, ttlcache.DefaultTTL)

	return awsUser
}

func (a *awsIdentityAdapter) selectAwsGroup(f *identitystoreClientFactory, awsGroupId string) *awsGroup {
	groupCacheItem := a.awsGroupCache.Get(awsGroupId)

	if groupCacheItem != nil {
		return groupCacheItem.Value()
	}

	describeGroupOutput, err := f.GetIdentitystoreClient().DescribeGroup(
		f.Ctx,
		&identitystore.DescribeGroupInput{
			IdentityStoreId: &a.settings.IdentityStoreId,
			GroupId:         &awsGroupId,
		})

	if err != nil {
		a.log.LogErrorText("Failed to describe AWS Identity Center group", "err", err, "awsGroupId", awsGroupId)
		return nil
	}

	externalId := ""

	for _, value := range describeGroupOutput.ExternalIds {
		if strings.HasPrefix(*value.Issuer, "https://scim.aws.com/") {
			externalId = *value.Id
		}
	}

	awsGroup := &awsGroup{
		GroupId:     *describeGroupOutput.GroupId,
		ExternalId:  externalId,
		DisplayName: *describeGroupOutput.DisplayName,
	}

	a.awsGroupCache.Set(awsGroupId, awsGroup, ttlcache.DefaultTTL)

	return awsGroup
}

func (a *awsIdentityAdapter) selectAwsUserGroupIds(f *identitystoreClientFactory, awsUserId string) []string {
	userGroupCacheItem := a.awsUserGroupCache.Get(awsUserId)

	if userGroupCacheItem != nil {
		return userGroupCacheItem.Value()
	}

	membershipOutput, err := f.GetIdentitystoreClient().ListGroupMembershipsForMember(
		f.Ctx,
		&identitystore.ListGroupMembershipsForMemberInput{
			IdentityStoreId: &a.settings.IdentityStoreId,
			MemberId: &identitystoreTypes.MemberIdMemberUserId{
				Value: awsUserId,
			},
		},
	)

	if err != nil {
		a.log.LogErrorText("Failed to list AWS Identity Center user`s group memberships", "err", err, "awsUserId", awsUserId)
		return nil
	}

	awsGroupIds := make([]string, 0, len(membershipOutput.GroupMemberships))

	for _, value := range membershipOutput.GroupMemberships {
		awsGroupIds = append(awsGroupIds, *value.GroupId)
	}

	return awsGroupIds
}

func (a *awsIdentityAdapter) SelectVpnUser(username string) *adapters.VpnUser {
	vpnUserCacheItem := a.vpnUserCache.Get(username)

	if vpnUserCacheItem != nil {
		return vpnUserCacheItem.Value()
	}

	clientFactory := &identitystoreClientFactory{
		Ctx:      context.TODO(),
		settings: a.settings,
		log:      a.log,
		client:   nil,
		once:     sync.Once{},
	}
	username = strings.ToLower(username)
	awsUserId := a.selectAwsUserId(clientFactory, username)

	if awsUserId == "" {
		return nil
	}

	awsUser := a.selectAwsUser(clientFactory, awsUserId)
	awsUserGroupIds := a.selectAwsUserGroupIds(clientFactory, awsUserId)
	awsGroups := make([]*awsGroup, 0, len(awsUserGroupIds))

	for _, awsGroupId := range awsUserGroupIds {
		awsGroup := a.selectAwsGroup(clientFactory, awsGroupId)

		if awsGroup != nil {
			awsGroups = append(awsGroups, awsGroup)
		}
	}

	radiusClass := "null"
	groupNamePattern := regexp.MustCompile(a.settings.RadiusClassFromGroupNamePattern)

	for _, awsGroup := range awsGroups {
		match := groupNamePattern.FindSubmatch([]byte(awsGroup.DisplayName))

		if len(match) > 1 {
			radiusClass = string(match[1])
			break
		}
	}

	vpnUser := &adapters.VpnUser{
		Username: awsUser.Username,
		Email:    awsUser.Email,
		Class:    radiusClass,
	}

	a.vpnUserCache.Set(username, vpnUser, ttlcache.DefaultTTL)

	return vpnUser
}

func NewAwsIdentityAdapter(s *settings.AppIdentityAwsSettings, l adapters.LoggingAdapter) *awsIdentityAdapter {
	return &awsIdentityAdapter{
		settings:          s,
		log:               l,
		awsUserIdCache:    ttlcache.New(ttlcache.WithTTL[string, string](5 * time.Minute)),
		awsUserCache:      ttlcache.New(ttlcache.WithTTL[string, *awsUser](5 * time.Minute)),
		awsUserGroupCache: ttlcache.New(ttlcache.WithTTL[string, []string](5 * time.Minute)),
		awsGroupCache:     ttlcache.New(ttlcache.WithTTL[string, *awsGroup](5 * time.Minute)),
		vpnUserCache:      ttlcache.New(ttlcache.WithTTL[string, *adapters.VpnUser](5 * time.Minute)),
	}
}
