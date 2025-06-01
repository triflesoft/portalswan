package http_server_portal_worker

import (
	"io"
	"net/http"
	"strings"
)

func (sc *httpServerPortalContext) externalHttpsStaticHandler(w http.ResponseWriter, r *http.Request) {
	ws := sc.workerState
	log := ws.AppState.LoggingAdapter
	path := strings.TrimPrefix(r.URL.Path, "/")
	file, err := sc.webrootOFS.Open(path)

	if err != nil {
		log.LogErrorText("Failed to find a file", "err", err, "path", path)
		http.Error(w, "", http.StatusNotFound)
		return
	}

	defer file.Close()

	data, err := io.ReadAll(file)

	if err != nil {
		log.LogErrorText("Failed to read a file", "err", err, "path", path)
		http.Error(w, "", http.StatusNotFound)
		return
	}

	if strings.HasSuffix(path, ".css") {
		w.Header().Set("Content-Type", "text/css")
	} else if strings.HasSuffix(path, ".html") {
		w.Header().Set("Content-Type", "text/html")
	} else if strings.HasSuffix(path, ".jpg") {
		w.Header().Set("Content-Type", "image/jpg")
	} else if strings.HasSuffix(path, ".js") {
		w.Header().Set("Content-Type", "application/javascript")
	} else if strings.HasSuffix(path, ".png") {
		w.Header().Set("Content-Type", "image/png")
	} else if strings.HasSuffix(path, ".svg") {
		w.Header().Set("Content-Type", "image/svg+xml")
	} else {
		w.Header().Set("Content-Type", "application/octet-steam")
	}

	w.Header().Set("Cache-Control", "private, max-age=604800")

	w.WriteHeader(200)
	w.Write(data)
}
