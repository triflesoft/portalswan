package http_server_portal_worker

import (
	"crypto/rand"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"sort"
	"time"

	"github.com/triflesoft/portalswan/internal/adapters/adapters"

	"golang.org/x/text/language"
)

var webuiTemplateNames = []string{
	"webui-error.html",
	"webui-index.html",
	"webui-self-service-create-password-done.html",
	"webui-self-service-create-password-fail.html",
	"webui-self-service-create-password-sent.html",
	"webui-self-service.html",
}

var plainTemplateNames = []string{
	"email-create-password-attachment-vpn-setup-linux.sh",
	"email-create-password-attachment-vpn-setup-windows.ps1",
	"email-create-password-body.html",
	"email-create-password-body.txt",
	"email-create-password-subject.txt",
}

type TemplateHandlerFunc func(r *http.Request, csrf string, bcp47Tags []language.Tag) (int, string, any, error)

func getBcp47TagsFromRequest(w http.ResponseWriter, r *http.Request) []language.Tag {
	tagWeights := map[language.Tag]float32{
		language.English: 0.1,
	}

	cookie, err := r.Cookie("bcp47tag")

	if (err == nil) && (cookie != nil) && (cookie.Value != "") {
		cookieTag, err := language.Parse(cookie.Value)

		if err == nil {
			tagWeights[cookieTag] = 1.9
		}
	}

	query := r.URL.Query()
	queryTagString := query.Get("bcp47tag")

	if queryTagString != "" {
		queryTag, err := language.Parse(queryTagString)

		if err == nil {
			tagWeights[queryTag] = 2.0

			cookie := &http.Cookie{
				Name:     "bcp47tag",
				Value:    queryTag.String(),
				Expires:  time.Now().Add(30 * 24 * time.Hour),
				HttpOnly: true,
				Path:     "/",
				Secure:   true,
			}

			http.SetCookie(w, cookie)
		}
	}

	acceptLanguageHeaderValues := r.Header["Accept-Language"]

	if (acceptLanguageHeaderValues != nil) && (len(acceptLanguageHeaderValues) >= 0) && (acceptLanguageHeaderValues[0] != "") {
		for _, headerValue := range acceptLanguageHeaderValues {
			tags, weights, err := language.ParseAcceptLanguage(headerValue)

			if err == nil && (len(tags) == len(weights)) {
				for tagIndex, tag := range tags {
					tagWeights[tag] = weights[tagIndex]
				}
			}
		}
	}

	bcp47Tags := make([]language.Tag, 0, len(tagWeights))

	for bcp47Tag := range tagWeights {
		bcp47Tags = append(bcp47Tags, bcp47Tag)
	}

	sort.SliceStable(bcp47Tags, func(i, j int) bool {
		return tagWeights[bcp47Tags[i]] > tagWeights[bcp47Tags[j]]
	})

	return bcp47Tags
}

type csrfData struct {
	Nonce     []byte
	IpAddress string
}

func (sc *httpServerPortalContext) csrfMiddleWare(innerHandler func(w http.ResponseWriter, r *http.Request, csrf string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ws := sc.workerState
		remoteAddr, _, err := net.SplitHostPort(r.RemoteAddr)

		if err != nil {
			logHttpRequest(ws, r, http.StatusInternalServerError, err)
			http.Error(w, "", http.StatusInternalServerError)
			return
		}

		r.RemoteAddr = remoteAddr

		if (r.Method == http.MethodPost) || (r.Method == http.MethodPut) {
			err := r.ParseForm()

			if err != nil {
				logHttpRequest(ws, r, http.StatusInternalServerError, err)
				http.Error(w, "", http.StatusInternalServerError)
				return
			}

			csrfFormValue := r.Form.Get("csrf")
			csrfFormData := &csrfData{
				Nonce:     []byte("<NULL>"),
				IpAddress: "<NULL>",
			}
			err = decryptToken(sc.workerState.AppState.LoggingAdapter, csrfFormValue, csrfFormData, 59*time.Minute)

			if err != nil {
				logHttpRequest(ws, r, http.StatusBadRequest, err)
				http.Error(w, "", http.StatusBadRequest)
				return
			}

			csrfCookie, err := r.Cookie("csrf")

			if err != nil {
				logHttpRequest(ws, r, http.StatusBadRequest, err)
				http.Error(w, "", http.StatusBadRequest)
				return
			}

			if csrfCookie.Value != csrfFormValue {
				logHttpRequest(ws, r, http.StatusBadRequest, errors.New("CSRF token mismatch"))
				http.Error(w, "", http.StatusBadRequest)
				return
			}

			if csrfFormData.IpAddress != remoteAddr {
				logHttpRequest(ws, r, http.StatusBadRequest, errors.New("IP mismatch"))
				http.Error(w, "", http.StatusBadRequest)
				return
			}
		}

		csrfData := &csrfData{
			Nonce:     make([]byte, 64),
			IpAddress: r.RemoteAddr,
		}

		rand.Read(csrfData.Nonce)
		csrfValue, err := encryptToken(sc.workerState.AppState.LoggingAdapter, csrfData)

		if err != nil {
			logHttpRequest(ws, r, http.StatusBadRequest, err)
			http.Error(w, "", http.StatusBadRequest)
			return
		}

		cookie := &http.Cookie{
			Name:     "csrf",
			Value:    csrfValue,
			Expires:  time.Now().Add(24 * time.Hour),
			HttpOnly: true,
			Path:     "/",
			Secure:   true,
		}
		http.SetCookie(w, cookie)
		innerHandler(w, r, csrfValue)
	}
}

type templateContext struct {
	RemoteAddr string
	Path       string
	Bcp47Tag   language.Tag
	Form       any
}

func (sc *httpServerPortalContext) loadTemplate(templateName string, bcp47Tags []language.Tag) string {
	for _, bcp47Tag := range bcp47Tags {
		f, err := sc.templateOFS.Open(fmt.Sprintf("%s/%s", bcp47Tag, templateName))

		if err == nil {
			defer f.Close()

			data, err := io.ReadAll(f)

			if err != nil {
				return ""
			}

			return string(data)
		}
	}

	return ""
}

func (sc *httpServerPortalContext) renderTemplate(l adapters.LoggingAdapter, wr io.Writer, r *http.Request, templateName string, contextData any, bcp47Tags []language.Tag) error {
	var err error

	for _, bcp47Tag := range bcp47Tags {
		templateCacheItem := sc.templateCache.Get(bcp47Tag)

		if (templateCacheItem == nil) || (templateCacheItem.IsExpired()) {
			templateMap := map[string]*template.Template{}
			isOld := true
			templateCacheItem, isOld = sc.templateCache.GetOrSet(bcp47Tag, templateMap)

			if !isOld {
				webuiBaseText := sc.loadTemplate("webui-base.html", bcp47Tags)

				if webuiBaseText == "" {
					return errors.New("failed to load base template")
				}

				for _, webuiTemplateName := range webuiTemplateNames {
					tmplText := sc.loadTemplate(webuiTemplateName, bcp47Tags)
					tmpl := template.New(webuiTemplateName)
					tmpl, err := tmpl.Parse(webuiBaseText)

					if err != nil {
						l.LogErrorText("Failed to load base template", "err", err, "webuiTemplateName", webuiTemplateName)

						return err
					}

					tmpl, err = tmpl.Parse(tmplText)

					if err != nil {
						l.LogErrorText("Failed to load template", "err", err, "webuiTemplateName", webuiTemplateName)

						return err
					}

					templateMap[webuiTemplateName] = tmpl
				}

				for _, plainTemplateName := range plainTemplateNames {
					tmplText := sc.loadTemplate(plainTemplateName, bcp47Tags)
					tmpl := template.New(plainTemplateName)
					tmpl, err = tmpl.Parse(tmplText)

					if err != nil {
						l.LogErrorText("Failed to load template", "err", err, "plainTemplateName", plainTemplateName)

						return err
					}

					templateMap[plainTemplateName] = tmpl
				}
			}
		}

		tmpl := templateCacheItem.Value()[templateName]

		if tmpl == nil {
			l.LogDebugText("Failed to find template", "templateName", templateName)
		} else {
			err = tmpl.Execute(
				wr,
				&templateContext{
					RemoteAddr: r.RemoteAddr,
					Path:       r.URL.Path,
					Bcp47Tag:   bcp47Tag,
					Form:       contextData,
				})

			if err != nil {
				l.LogErrorText("Failed to render template", "err", err, "templateName", templateName)
			} else {
				return nil
			}
		}
	}

	return errors.New("failed to find template")
}

func (sc *httpServerPortalContext) templateMiddleware(templateHandler TemplateHandlerFunc) func(w http.ResponseWriter, r *http.Request, csrf string) {
	return func(w http.ResponseWriter, r *http.Request, csrf string) {
		ws := sc.workerState
		bcp47Tags := getBcp47TagsFromRequest(w, r)
		statusCode, templateName, contextData, err := templateHandler(r, csrf, bcp47Tags)

		if err != nil {
			logHttpRequest(ws, r, http.StatusInternalServerError, err)
			http.Error(w, "", http.StatusInternalServerError)
			return
		}

		if (statusCode == http.StatusMovedPermanently) || (statusCode == http.StatusFound) {
			logHttpRequest(ws, r, statusCode, err)
			http.Redirect(w, r, templateName, statusCode)
			return
		}

		h := w.Header()
		h.Del("Content-Length")
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("X-Content-Type-Options", "nosniff")

		err = sc.renderTemplate(ws.AppState.LoggingAdapter, w, r, templateName, contextData, bcp47Tags)

		if err != nil {
			logHttpRequest(ws, r, http.StatusInternalServerError, err)
			http.Error(w, "", http.StatusInternalServerError)
		}
	}
}
