package aws_email_adapter

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	sesv2Types "github.com/aws/aws-sdk-go-v2/service/sesv2/types"
	"github.com/triflesoft/portalswan/internal/adapters/adapters"
	"github.com/triflesoft/portalswan/internal/settings"
)

type awsEmailAdapter struct {
	settings *settings.AppEmailAwsSettings
	log      adapters.LoggingAdapter
}

func (a *awsEmailAdapter) SendEmail(recipientAddress string, subject string, bodyText string, bodyHtml string, attachments map[string]adapters.EmailAttachment) {
	defer func() {
		if err := recover(); err != nil {
			a.log.LogErrorText("Failed to generate email", "err", err, "recipientAddress", recipientAddress, "subject", subject)
		}
	}()

	ctx := context.TODO()
	awsConfig, err := config.LoadDefaultConfig(ctx, config.WithRegion(a.settings.SesRegion))

	if err != nil {
		a.log.LogErrorText("Failed to load default AWS config", "err", err)
		return
	}

	sesv2Client := sesv2.NewFromConfig(awsConfig)
	sesAttachments := make([]sesv2Types.Attachment, 0, len(attachments))

	for name, attachment := range attachments {
		if attachment.ContentID == "" {
			sesAttachments = append(sesAttachments, sesv2Types.Attachment{
				FileName:                aws.String(name),
				RawContent:              attachment.Content,
				ContentDisposition:      sesv2Types.AttachmentContentDispositionAttachment,
				ContentTransferEncoding: sesv2Types.AttachmentContentTransferEncodingBase64,
				ContentType:             &attachment.ContentType,
			})

		} else {
			sesAttachments = append(sesAttachments, sesv2Types.Attachment{
				FileName:                aws.String(name),
				RawContent:              attachment.Content,
				ContentDisposition:      sesv2Types.AttachmentContentDispositionInline,
				ContentTransferEncoding: sesv2Types.AttachmentContentTransferEncodingBase64,
				ContentType:             &attachment.ContentType,
				ContentId:               &attachment.ContentID,
			})
		}
	}

	_, err = sesv2Client.SendEmail(
		ctx,
		&sesv2.SendEmailInput{
			Content: &sesv2Types.EmailContent{
				Simple: &sesv2Types.Message{
					Subject: &sesv2Types.Content{
						Data:    &subject,
						Charset: aws.String("UTF-8"),
					},
					Body: &sesv2Types.Body{
						Html: &sesv2Types.Content{
							Data:    &bodyHtml,
							Charset: aws.String("UTF-8"),
						},
						Text: &sesv2Types.Content{
							Data:    &bodyText,
							Charset: aws.String("UTF-8"),
						},
					},
					Attachments: sesAttachments,
				},
			},
			Destination: &sesv2Types.Destination{
				ToAddresses: []string{"r.akopov@wenroll.com"},
			},
			FromEmailAddress: aws.String("r.akopov@wenroll.com"),
		})

	if err != nil {
		a.log.LogErrorText("Failed to send email", "err", err, "recipientAddress", recipientAddress, "subject", subject)
		return
	}

	a.log.LogDebugText("Sent email", "recipientAddress", recipientAddress, "subject", subject)
}

func NewAwsEmailAdapter(s *settings.AppEmailAwsSettings, l adapters.LoggingAdapter) *awsEmailAdapter {
	return &awsEmailAdapter{
		settings: s,
		log:      l,
	}
}
