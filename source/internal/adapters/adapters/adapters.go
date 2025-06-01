package adapters

import "io/fs"

type VpnUser struct {
	Username string
	Email    string
	Class    string
}

type IdentityAdapter interface {
	SelectVpnUser(username string) *VpnUser
}

type CredentialsAdapter interface {
	SelectIpAddresses(vpnUser *VpnUser) []string
	SelectNtPassword(vpnUser *VpnUser, ipAddress string) string
	UpdateNtPassword(vpnUser *VpnUser, ipAddress string, clearTextPassword string)
}

type EmailAttachment struct {
	Content     []byte
	ContentID   string
	ContentType string
}

func NewEmailAttachmentFromFile(log LoggingAdapter, fs fs.ReadFileFS, path string, contentType string, contentID string) EmailAttachment {
	data, err := fs.ReadFile(path)

	if err != nil {
		log.LogErrorText("Failed to load email attachment", "err", err)
		data = []byte{}
	}

	return EmailAttachment{
		Content:     data,
		ContentID:   contentID,
		ContentType: contentType,
	}
}

type EmailAdapter interface {
	SendEmail(recipientAddress string, subject string, bodyText string, bodyHtml string, attachments map[string]EmailAttachment)
}

type LoggingAdapter interface {
	LogDebugText(msg string, args ...any)
	LogErrorText(msg string, args ...any)
	LogInfoText(channel string, msg string, args ...any)
	LogInfoJson(channel string, msg any)
}
