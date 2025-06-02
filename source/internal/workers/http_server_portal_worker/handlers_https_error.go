package http_server_portal_worker

import (
	"net/http"

	"golang.org/x/text/language"
)

func (sc *httpServerPortalContext) externalHttpsErrorHandler(r *http.Request, csrf string, bcp47Tags []language.Tag) (int, string, any, error) {
	return http.StatusNotFound, "webui-error.html", nil, nil
}
