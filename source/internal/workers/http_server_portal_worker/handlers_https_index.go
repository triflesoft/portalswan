package http_server_portal_worker

import (
	"net/http"

	"golang.org/x/text/language"
)

type indexTemplateContext struct {
	PrivateHostname string
}

func (sc *httpServerPortalContext) externalHttpsIndexHandler(r *http.Request, csrf string, bcp47Tags []language.Tag) (int, string, any, error) {
	if r.URL.Path != "/" {
		return http.StatusNotFound, "webui-error.html", nil, nil
	}

	templateContext := indexTemplateContext{
		PrivateHostname: sc.privateHostname,
	}

	return http.StatusOK, "webui-index.html", templateContext, nil
}
