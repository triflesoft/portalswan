package http_server_portal_worker

import (
	"context"
	"crypto/tls"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"portalswan/internal/state"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fernet/fernet-go"
	ttlcache "github.com/jellydator/ttlcache/v3"
	"golang.org/x/text/language"
)

type httpServerPortalContext struct {
	workerState     *state.WorkerState
	webrootOFS      *overlayFS
	templateOFS     *overlayFS
	templateCache   *ttlcache.Cache[language.Tag, map[string]*template.Template]
	tokenCache      *ttlcache.Cache[string, bool]
	tokenKey        *fernet.Key
	privateHostname string
}

type certificateStore struct {
	mtx             sync.RWMutex
	certificate     *tls.Certificate
	CertificatePath string
	PrivateKeyPath  string
}

func (cs *certificateStore) LoadCertificate() error {
	certificate, err := tls.LoadX509KeyPair(cs.CertificatePath, cs.PrivateKeyPath)

	if err != nil {
		return err
	}

	cs.mtx.Lock()

	defer cs.mtx.Unlock()

	cs.certificate = &certificate

	return nil
}

func (cs *certificateStore) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cs.mtx.RLock()
	defer cs.mtx.RUnlock()

	if cs.certificate == nil {
		return nil, fmt.Errorf("failed to load certificate from %s", cs.CertificatePath)
	}

	return cs.certificate, nil
}

func HttpServerPortalWorker(ws *state.WorkerState) bool {
	webrootSubFS, err := fs.Sub(webrootFS, "webroot")
	log := ws.AppState.LoggingAdapter

	if err != nil {
		log.LogErrorText("Failed to create virtual filesystem", "err", err)
		return false
	}

	webrootOFS := NewOverlayFS(os.DirFS(filepath.Join(ws.AppState.GetBaseFileSystemPath(), "webroot")), webrootSubFS)
	templateSubFS, err := fs.Sub(templateFS, "template")

	if err != nil {
		log.LogErrorText("Failed to create virtual filesystem", "err", err)
		return false
	}

	templateOFS := NewOverlayFS(os.DirFS(filepath.Join(ws.AppState.GetBaseFileSystemPath(), "template")), templateSubFS)

	serverSettings := ws.AppState.GetServerSettings()
	serverContext := httpServerPortalContext{
		workerState:     ws,
		webrootOFS:      webrootOFS,
		templateOFS:     templateOFS,
		templateCache:   ttlcache.New(ttlcache.WithTTL[language.Tag, map[string]*template.Template](1 * time.Minute)),
		tokenCache:      ttlcache.New(ttlcache.WithTTL[string, bool](120 * time.Minute)),
		tokenKey:        &fernet.Key{},
		privateHostname: serverSettings.VerificationHostname,
	}

	serverContext.tokenKey.Generate()

	go serverContext.templateCache.Start()
	go serverContext.tokenCache.Start()

	httpMux := http.NewServeMux()
	httpMux.HandleFunc(
		"/favicon.ico",
		serverContext.externalHttpsStaticHandler)
	httpMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		httpsURL := "https://" + r.Host + r.RequestURI
		http.Redirect(w, r, httpsURL, http.StatusMovedPermanently)
	})
	httpServer := &http.Server{
		Addr:    ":80",
		Handler: httpMux,
	}

	go func() {
		for {
			if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
				log.LogErrorText("Failed to start HTTP server", "err", err)
			}

			time.Sleep(time.Second)
		}
	}()

	httpsMux := http.NewServeMux()
	httpsMux.HandleFunc("/static/", serverContext.externalHttpsStaticHandler)
	httpsMux.HandleFunc("/favicon.ico", serverContext.externalHttpsStaticHandler)
	httpsMux.HandleFunc("/verification/", serverContext.publicHttpsVerificationHandler)
	httpsMux.HandleFunc(
		"/error/",
		serverContext.csrfMiddleWare(serverContext.templateMiddleware(serverContext.externalHttpsErrorHandler)))
	httpsMux.HandleFunc(
		"/self-service/create-password/sent/",
		serverContext.csrfMiddleWare(serverContext.templateMiddleware(serverContext.externalHttpsSelfServiceCreatePasswordSentHandler)))
	httpsMux.HandleFunc(
		"/self-service/create-password/done/",
		serverContext.csrfMiddleWare(serverContext.templateMiddleware(serverContext.externalHttpsSelfServiceCreatePasswordDoneHandler)))
	httpsMux.HandleFunc(
		"/self-service/",
		serverContext.csrfMiddleWare(serverContext.templateMiddleware(serverContext.externalHttpsSelfServiceHandler)))
	httpsMux.HandleFunc(
		"/",
		serverContext.csrfMiddleWare(serverContext.templateMiddleware(serverContext.externalHttpsIndexHandler)))

	certStore := certificateStore{
		CertificatePath: serverSettings.TlsCertificatePath,
		PrivateKeyPath:  serverSettings.TlsPrivateKeyPath,
	}

	httpsServer := &http.Server{
		Addr: ":443",
		TLSConfig: &tls.Config{
			GetCertificate: certStore.GetCertificate,
			MinVersion:     tls.VersionTLS12,
		},
		Handler: httpsMux,
	}

	isRunning := atomic.Bool{}
	isRunning.Store(true)

	go func() {
		for {
			if certStore.LoadCertificate() == nil {
				if err := httpsServer.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
					isRunning.Store(false)
					log.LogErrorText("Failed to start HTTPS server", "err", err)
				}
			}

			time.Sleep(time.Second)
		}
	}()

	go func() {
		ticker := time.NewTicker(30 * time.Minute)

		for {
			select {
			case <-ticker.C:
				certStore.LoadCertificate()
			case <-ws.QuitChan:
				log.LogDebugText("Terminating Portal HTTP...")
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()

				if err := httpServer.Shutdown(ctx); err != nil {
					log.LogErrorText("Failed to stop HTTP server", "err", err)
				}

				if err := httpsServer.Shutdown(ctx); err != nil {
					log.LogErrorText("Failed to stop HTTPS server", "err", err)
				}

				log.LogDebugText("Portal HTTP termination completed")
				ws.ReportQuitCompleted()
				return
			}
		}
	}()

	time.Sleep(100 * time.Millisecond)

	log.LogDebugText("Portal HTTP initalization completed")
	ws.ReportInitCompleted()

	return isRunning.Load()
}
