package http_server_portal_worker

import (
	"net/http"
)

func (sc *httpServerPortalContext) externalHttpsErrorHandler(r *http.Request, csrf string, bcp47Tags []string) (int, string, any, error) {
	return http.StatusNotFound, "webui-error.html", nil, nil
}
