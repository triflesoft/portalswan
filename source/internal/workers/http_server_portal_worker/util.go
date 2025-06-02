package http_server_portal_worker

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/triflesoft/portalswan/internal/adapters/adapters"
	"github.com/triflesoft/portalswan/internal/state"

	"github.com/fernet/fernet-go"
	"golang.org/x/text/language"
)

const LogChannelName = "WebUI"

var tokenKey []*fernet.Key

func init() {
	tokenKey = []*fernet.Key{
		{},
	}

	tokenKey[0].Generate()
}

type httpRequestLog struct {
	Status    int                 `json:"status"`
	Uri       string              `json:"uri"`
	Method    string              `json:"method"`
	Headers   map[string][]string `json:"headers"`
	IpAddress string              `json:"ip_address"`
	Error     string              `json:"error"`
}

func logHttpRequest(ws *state.WorkerState, r *http.Request, status int, err error) {
	log := ws.AppState.LoggingAdapter

	var errStr string

	if err != nil {
		errStr = err.Error()
	}

	message := httpRequestLog{
		Status:    status,
		Uri:       r.URL.String(),
		Method:    r.Method,
		Headers:   r.Header,
		IpAddress: r.RemoteAddr,
		Error:     errStr,
	}

	log.LogInfoJson(LogChannelName, message)
}

func encryptToken(loggingAdapter adapters.LoggingAdapter, cleartext any) (string, error) {
	cleartextData, err := json.Marshal(cleartext)

	if err != nil {
		loggingAdapter.LogErrorText("Failed to marshal JSON", "err", err)

		return "", err
	}

	encryptedData, err := fernet.EncryptAndSign(cleartextData, tokenKey[0])

	if err != nil {
		loggingAdapter.LogErrorText("Failed to encrypt fernet data", "err", err)

		return "", err
	}

	return base64.URLEncoding.EncodeToString(encryptedData), nil
}

func decryptToken(loggingAdapter adapters.LoggingAdapter, encryptedText string, cleartext any, ttl time.Duration) error {
	encryptedData, err := base64.URLEncoding.DecodeString(encryptedText)

	if err != nil {
		loggingAdapter.LogErrorText("Failed to decode Base64 data", "err", err)

		return err
	}

	cleartextData := fernet.VerifyAndDecrypt(encryptedData, ttl, tokenKey)

	if cleartextData == nil {
		loggingAdapter.LogErrorText("Failed to decrypt fernet data")

		return errors.New("failed to decrypt fernet data")
	}

	return json.Unmarshal(cleartextData, cleartext)
}

func (sc *httpServerPortalContext) renderTemplateToString(r *http.Request, templateName string, contextData any, bcp47Tags []language.Tag) string {
	ws := sc.workerState
	log := ws.AppState.LoggingAdapter
	bldr := strings.Builder{}

	if err := sc.renderTemplate(log, &bldr, r, templateName, contextData, bcp47Tags); err != nil {
		log.LogErrorText("Failed to render template", "err", err, "templateName", templateName)

		return "!!!TEMPLATE RENDERING ERROR!!!"
	}

	return bldr.String()
}
