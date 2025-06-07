package http_server_portal_worker

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/triflesoft/portalswan/internal/adapters/adapters"

	"golang.org/x/text/language"
)

type webAccessToken struct {
	Username  string `json:"username"`
	IpAddress string `json:"ip_address"`
}

type selfServiceTemplateContext struct {
	CSRF string
}

type createPasswordSentTemplateContext struct {
	ServerHost          string
	IpAddress           string
	Username            string
	Token               string
	DnsSuffix           string
	DnsServers          []string
	DestinationPrefixes []string
}

type createPasswordDoneTemplateContext struct {
	IpAddress string
	Username  string
	Password  template.HTML
}

func (sc *httpServerPortalContext) externalHttpsSelfServiceHandler(r *http.Request, csrf string, bcp47Tags []language.Tag) (int, string, any, error) {
	ws := sc.workerState
	log := ws.AppState.LoggingAdapter

	if r.Method == http.MethodPost {
		r.ParseForm()
		formAction := r.Form.Get("action")

		switch formAction {
		case "create-password":
			formEmail := r.Form.Get("email")
			vpnUser := ws.AppState.IdentityAdapter.SelectVpnUser(formEmail)

			if vpnUser == nil {
				log.LogErrorText("Failed to get VPN user by username", "remoteIpAddress", r.RemoteAddr, "username", formEmail)

				return http.StatusFound, "/self-service/create-password/sent/", nil, nil
			}
			token := &webAccessToken{
				Username:  formEmail,
				IpAddress: r.RemoteAddr,
			}

			tokenEncryptedText, err := encryptToken(log, token)

			if err != nil {
				log.LogErrorText("Failed to encrypt create password token", "err", err, "remoteIpAddress", r.RemoteAddr)

				return http.StatusFound, "/self-service/create-password/sent/", nil, nil
			}

			templateContext := &createPasswordSentTemplateContext{
				ServerHost:          r.Host,
				IpAddress:           r.RemoteAddr,
				Username:            vpnUser.Username,
				Token:               tokenEncryptedText,
				DnsSuffix:           ws.AppState.GetClientSettings().DnsSuffix,
				DnsServers:          ws.AppState.GetClientSettings().DnsServers,
				DestinationPrefixes: ws.AppState.GetClientSettings().DestinationPrefixes,
			}

			subject := sc.renderTemplateToString(r, "email-create-password-subject.txt", templateContext, bcp47Tags)
			bodyText := sc.renderTemplateToString(r, "email-create-password-body.txt", templateContext, bcp47Tags)
			bodyHtml := sc.renderTemplateToString(r, "email-create-password-body.html", templateContext, bcp47Tags)
			linuxSetupScriptContents := []byte(sc.renderTemplateToString(r, "email-create-password-attachment-vpn-setup-linux.sh", templateContext, bcp47Tags))
			windowsSetupScriptContents := []byte(sc.renderTemplateToString(r, "email-create-password-attachment-vpn-setup-windows.ps1", templateContext, bcp47Tags))
			zipData := &bytes.Buffer{}

			{
				zipWriter := zip.NewWriter(zipData)
				linuxWriter, err := zipWriter.Create(fmt.Sprintf("VPN-Linux-[%s].sh", r.Host))

				if err != nil {
					log.LogErrorText("Failed to create ZIP file", "err", err, "remoteIpAddress", r.RemoteAddr)

					return http.StatusFound, "/self-service/create-password/sent/", nil, nil
				}

				n, err := linuxWriter.Write(linuxSetupScriptContents)

				if (err != nil) || (n != len(linuxSetupScriptContents)) {
					log.LogErrorText("Failed to create ZIP file", "err", err, "remoteIpAddress", r.RemoteAddr)

					return http.StatusFound, "/self-service/create-password/sent/", nil, nil
				}

				windowsWriter, err := zipWriter.Create(fmt.Sprintf("VPN-Windows-[%s].ps1", r.Host))

				if err != nil {
					log.LogErrorText("Failed to create ZIP file", "err", err, "remoteIpAddress", r.RemoteAddr)

					return http.StatusFound, "/self-service/create-password/sent/", nil, nil
				}

				n, err = windowsWriter.Write(windowsSetupScriptContents)

				if (err != nil) || (n != len(windowsSetupScriptContents)) {
					log.LogErrorText("Failed to create ZIP file", "err", err, "remoteIpAddress", r.RemoteAddr)

					return http.StatusFound, "/self-service/create-password/sent/", nil, nil
				}

				if err = zipWriter.Close(); err != nil {
					log.LogErrorText("Failed to create ZIP file", "err", err, "remoteIpAddress", r.RemoteAddr)

					return http.StatusFound, "/self-service/create-password/sent/", nil, nil
				}
			}

			ws.AppState.EmailAdapter.SendEmail(
				vpnUser.Email,
				subject,
				bodyText,
				bodyHtml,
				map[string]adapters.EmailAttachment{
					"android-accept.png":   adapters.NewEmailAttachmentFromFile(ws.AppState.LoggingAdapter, attachmentFS, "attachment/android-accept.png", "image/png", "android-accept"),
					"android-eye.png":      adapters.NewEmailAttachmentFromFile(ws.AppState.LoggingAdapter, attachmentFS, "attachment/android-eye.png", "image/png", "android-eye"),
					"android-back.png":     adapters.NewEmailAttachmentFromFile(ws.AppState.LoggingAdapter, attachmentFS, "attachment/android-back.png", "image/png", "android-back"),
					"android-cancel.png":   adapters.NewEmailAttachmentFromFile(ws.AppState.LoggingAdapter, attachmentFS, "attachment/android-cancel.png", "image/png", "android-cancel"),
					"android-home.png":     adapters.NewEmailAttachmentFromFile(ws.AppState.LoggingAdapter, attachmentFS, "attachment/android-home.png", "image/png", "android-home"),
					"android-overview.png": adapters.NewEmailAttachmentFromFile(ws.AppState.LoggingAdapter, attachmentFS, "attachment/android-overview.png", "image/png", "android-overview"),
					"android-status.png":   adapters.NewEmailAttachmentFromFile(ws.AppState.LoggingAdapter, attachmentFS, "attachment/android-status.png", "image/png", "android-status"),
					"android-toggle.png":   adapters.NewEmailAttachmentFromFile(ws.AppState.LoggingAdapter, attachmentFS, "attachment/android-toggle.png", "image/png", "android-toggle"),
					"android-updown.png":   adapters.NewEmailAttachmentFromFile(ws.AppState.LoggingAdapter, attachmentFS, "attachment/android-updown.png", "image/png", "android-updown"),
					"logo.png":             adapters.NewEmailAttachmentFromFile(ws.AppState.LoggingAdapter, attachmentFS, "attachment/logo.png", "image/png", "logo"),
					"macos-updown.png":     adapters.NewEmailAttachmentFromFile(ws.AppState.LoggingAdapter, attachmentFS, "attachment/macos-updown.png", "image/png", "macos-updown"),
					fmt.Sprintf("VPN-[%s].zip", r.Host): {
						Content:     zipData.Bytes(),
						ContentID:   "",
						ContentType: "application/zip",
					},
				})

			return http.StatusFound, "/self-service/create-password/sent/", nil, nil
		}
	}

	templateContext := &selfServiceTemplateContext{
		CSRF: csrf,
	}

	return http.StatusOK, "webui-self-service.html", templateContext, nil
}

func (sc *httpServerPortalContext) externalHttpsSelfServiceCreatePasswordSentHandler(r *http.Request, csrf string, bcp47Tags []language.Tag) (int, string, any, error) {
	return http.StatusCreated, "webui-self-service-create-password-sent.html", nil, nil
}

func (sc *httpServerPortalContext) externalHttpsSelfServiceCreatePasswordDoneHandler(r *http.Request, csrf string, bcp47Tags []language.Tag) (int, string, any, error) {
	ws := sc.workerState
	log := ws.AppState.LoggingAdapter
	query := r.URL.Query()
	tokenText := query.Get("token")

	if tokenText == "" {
		log.LogErrorText("Missing create password token", "remoteIpAddress", r.RemoteAddr)

		return http.StatusUnauthorized, "webui-self-service-create-password-fail.html", nil, nil
	}

	if sc.tokenCache.Has(tokenText) {
		log.LogErrorText("Reused create password token", "remoteIpAddress", r.RemoteAddr)

		return http.StatusUnauthorized, "webui-self-service-create-password-fail.html", nil, nil
	}

	sc.tokenCache.Set(tokenText, true, 61*time.Minute)

	token := &webAccessToken{
		Username:  "<NULL>",
		IpAddress: "<NULL>",
	}
	err := decryptToken(log, tokenText, &token, 60*time.Minute)

	if err != nil {
		log.LogErrorText("Failed to descrupt token", "remoteIpAddress", r.RemoteAddr)

		return http.StatusUnauthorized, "webui-self-service-create-password-fail.html", nil, nil
	}

	if token.IpAddress != r.RemoteAddr {
		log.LogErrorText("IP address mismatch", "remoteIpAddress", r.RemoteAddr, "tokenIpAddress", token.IpAddress)

		return http.StatusUnauthorized, "webui-self-service-create-password-fail.html", nil, nil
	}

	passwordAlphabet := "ABCDEFHKLMNPRTUVWXYZabcdefhkmnpqrstuvwxyz23478"
	passwordLength := 20
	passwordData := make([]byte, passwordLength)
	passwordSymbolData := make([]byte, 2)
	passwordSymbolIndex := 0
	maxRandomValue := (65536 / len(passwordAlphabet)) * len(passwordAlphabet)

	for passwordSymbolIndex < len(passwordData) {
		dataLength, err := rand.Reader.Read(passwordSymbolData)

		if (err == nil) && (dataLength == len(passwordSymbolData)) {
			randomValue := int(binary.BigEndian.Uint16(passwordSymbolData))

			if randomValue < maxRandomValue {
				passwordData[passwordSymbolIndex] = passwordAlphabet[randomValue%len(passwordAlphabet)]
				passwordSymbolIndex++
			}
		}
	}

	vpnUser := ws.AppState.IdentityAdapter.SelectVpnUser(token.Username)

	if vpnUser == nil {
		log.LogErrorText("Failed to get VPN user by username", "remoteIpAddress", r.RemoteAddr, "username", token.Username)

		return http.StatusUnauthorized, "webui-self-service-create-password-fail.html", nil, nil
	}

	ws.AppState.CredentialsAdapter.UpdateNtPassword(vpnUser, r.RemoteAddr, string(passwordData))
	htmlPasswordBuilder := strings.Builder{}

	for _, passwordSymbol := range passwordData {
		if (passwordSymbol >= '0') && (passwordSymbol <= '9') {
			htmlPasswordBuilder.WriteString(fmt.Sprintf("<span class=\"text-red-800\">%c</span>", passwordSymbol))
		} else if (passwordSymbol >= 'a') && (passwordSymbol <= 'z') {
			htmlPasswordBuilder.WriteString(fmt.Sprintf("<span class=\"text-blue-800\">%c</span>", passwordSymbol))
		} else if (passwordSymbol >= 'A') && (passwordSymbol <= 'Z') {
			htmlPasswordBuilder.WriteString(fmt.Sprintf("<span class=\"text-green-800\">%c</span>", passwordSymbol))
		} else {
			htmlPasswordBuilder.WriteByte(passwordSymbol)
		}
	}

	htmlPassword := htmlPasswordBuilder.String()
	templateContext := &createPasswordDoneTemplateContext{
		IpAddress: r.RemoteAddr,
		Username:  token.Username,
		Password:  template.HTML(htmlPassword),
	}

	return http.StatusOK, "webui-self-service-create-password-done.html", templateContext, nil
}
