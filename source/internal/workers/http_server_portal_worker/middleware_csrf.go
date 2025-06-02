package http_server_portal_worker

import (
	"crypto/rand"
	"errors"
	"net"
	"net/http"
	"time"
)

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
