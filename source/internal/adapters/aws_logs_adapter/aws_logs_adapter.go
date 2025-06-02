package aws_logs_adapter

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cloudwatchlogsTypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/triflesoft/portalswan/internal/settings"
)

type cloudWatchLogsWriterHandler struct {
	region         string
	group          string
	stream         string
	logger         *slog.Logger
	fallbackLogger *slog.Logger
}

func (h *cloudWatchLogsWriterHandler) Write(p []byte) (n int, err error) {
	os.Stdout.Write(p)

	if len(p) > 1 && p[len(p)-1] >= 32 {
		os.Stdout.Write([]byte{10})
	}

	ctx := context.TODO()
	awsConfig, err := config.LoadDefaultConfig(ctx, config.WithRegion(h.region))

	if err != nil {
		h.fallbackLogger.Error("Failed to load default AWS config", "err", err)
		return
	}

	logsClient := cloudwatchlogs.NewFromConfig(awsConfig)
	timestamp := time.Now().UnixMilli()
	message := string(p)
	logEvents := []cloudwatchlogsTypes.InputLogEvent{{
		Message:   &message,
		Timestamp: &timestamp,
	}}

	_, err = logsClient.PutLogEvents(
		ctx,
		&cloudwatchlogs.PutLogEventsInput{
			LogEvents:     logEvents,
			LogGroupName:  &h.group,
			LogStreamName: &h.stream,
		},
	)

	if err != nil {
		h.fallbackLogger.Error("Failed to put log events", "err", err)
		return
	}

	return len(p), nil
}

type awsLoggingAdapter struct {
	settings       *settings.AppLoggingAwsSettings
	handlers       *map[string]*cloudWatchLogsWriterHandler
	fallbackLogger *slog.Logger
}

func (a *awsLoggingAdapter) LogDebugText(msg string, args ...any) {
	handler := (*a.handlers)["Debug"]

	if handler == nil {
		handler = NewCloudWatchLogsWriterHandler(a, "Debug", a.fallbackLogger)
		(*a.handlers)["Debug"] = handler
	}

	if handler != nil {
		handler.logger.Debug(msg, args...)
	}
}

func (a *awsLoggingAdapter) LogErrorText(msg string, args ...any) {
	handler := (*a.handlers)["Error"]

	if handler == nil {
		handler = NewCloudWatchLogsWriterHandler(a, "Error", a.fallbackLogger)
		(*a.handlers)["Error"] = handler
	}

	if handler != nil {
		handler.logger.Error(msg, args...)
	}
}

func (a *awsLoggingAdapter) LogInfoText(channel string, msg string, args ...any) {
	handler := (*a.handlers)[channel]

	if handler == nil {
		handler = NewCloudWatchLogsWriterHandler(a, channel, a.fallbackLogger)
		(*a.handlers)[channel] = handler
	}

	if handler != nil {
		handler.logger.Info(msg, args...)
	}
}

func (a *awsLoggingAdapter) LogInfoJson(channel string, msg any) {
	handler := (*a.handlers)[channel]

	if handler == nil {
		handler = NewCloudWatchLogsWriterHandler(a, channel, a.fallbackLogger)
		(*a.handlers)[channel] = handler
	}

	if handler != nil {
		messageData, err := json.Marshal(msg)

		if err != nil {
			a.fallbackLogger.Error("Failed to marshal JSON", "err", err)
			return
		}

		handler.Write(messageData)
	}
}

func NewCloudWatchLogsWriterHandler(a *awsLoggingAdapter, name string, fallbackLogger *slog.Logger) *cloudWatchLogsWriterHandler {
	handler := &cloudWatchLogsWriterHandler{
		region:         a.settings.CloudWatchLogRegion,
		group:          a.settings.CloudWatchLogGroup,
		stream:         name,
		logger:         fallbackLogger,
		fallbackLogger: fallbackLogger,
	}
	handler.logger = slog.New(slog.NewJSONHandler(handler, &slog.HandlerOptions{AddSource: false, Level: slog.LevelDebug}))

	ctx := context.TODO()
	awsConfig, err := config.LoadDefaultConfig(ctx, config.WithRegion(a.settings.CloudWatchLogRegion))

	if err != nil {
		fallbackLogger.Error("Failed to load default AWS config", "err", err)
		return nil
	}

	logsClient := cloudwatchlogs.NewFromConfig(awsConfig)
	_, err = logsClient.CreateLogStream(
		ctx,
		&cloudwatchlogs.CreateLogStreamInput{
			LogGroupName:  &a.settings.CloudWatchLogGroup,
			LogStreamName: &name,
		})

	if err != nil {
		var raee *cloudwatchlogsTypes.ResourceAlreadyExistsException

		if !errors.As(err, &raee) {
			fallbackLogger.Error("Failed to create CloudWatch Logs stream", "err", err)
			return nil
		}
	}

	return handler
}

func NewAwsLoggingAdapter(s *settings.AppLoggingAwsSettings) *awsLoggingAdapter {
	return &awsLoggingAdapter{
		settings:       s,
		handlers:       &map[string]*cloudWatchLogsWriterHandler{},
		fallbackLogger: slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{AddSource: false, Level: slog.LevelDebug})),
	}
}
