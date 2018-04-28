package server_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	. "github.com/gearnode/csp-handler/server"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
)

var (
	a = App{}
)

func init() {
	a.Initialize()
}

func executeRequest(req *http.Request) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	a.Router.ServeHTTP(rr, req)

	return rr
}

func TestHelperNotFound(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", nil)
	response := executeRequest(req)
	assert.Equal(t, http.StatusNotFound, response.Code)
	assert.Equal(t, response.Body.String(), "404 page not found\n")

	req, _ = http.NewRequest("GET", "/foobar", nil)
	response = executeRequest(req)
	assert.Equal(t, http.StatusNotFound, response.Code)
	assert.Equal(t, response.Body.String(), "404 page not found\n")
}

func TestHandlerSuccess(t *testing.T) {
	csp := CSP{
		Report: Report{
			DocumentURI:       "https://example.com/foo/bar",
			Referrer:          "https://www.google.com/",
			ViolatedDirective: "default-src self",
			OriginalPolicy:    "default-src self; report-uri /reports",
			BlockedURI:        "http://foobar.com",
		},
	}

	v, err := json.Marshal(csp)
	assert.NoError(t, err)

	logger, hook := test.NewNullLogger()
	a.Logger = logger

	req, _ := http.NewRequest("POST", "/report", bytes.NewBuffer(v))
	response := executeRequest(req)

	assert.Equal(t, http.StatusOK, response.Code)
	assert.Equal(t, 1, len(hook.Entries))
	assert.Equal(t, logrus.InfoLevel, hook.LastEntry().Level)
	assert.Equal(t, "new content security policy violation received", hook.LastEntry().Message)
	assert.Equal(t, csp.Report.DocumentURI, hook.LastEntry().Data["document-uri"])
	assert.Equal(t, csp.Report.Referrer, hook.LastEntry().Data["referrer"])
	assert.Equal(t, csp.Report.ViolatedDirective, hook.LastEntry().Data["violated-directive"])
	assert.Equal(t, csp.Report.OriginalPolicy, hook.LastEntry().Data["original-policy"])
	assert.Equal(t, csp.Report.BlockedURI, hook.LastEntry().Data["blocked-uri"])

	hook.Reset()
	assert.Nil(t, hook.LastEntry())
}

func TestHandlerWithNotAllowedHTTPVerb(t *testing.T) {
	req, _ := http.NewRequest("GET", "/report", bytes.NewBuffer([]byte("{}")))
	response := executeRequest(req)
	assert.Equal(t, http.StatusMethodNotAllowed, response.Code)

	req, _ = http.NewRequest("PUT", "/report", bytes.NewBuffer([]byte("{}")))
	response = executeRequest(req)
	assert.Equal(t, http.StatusMethodNotAllowed, response.Code)

	req, _ = http.NewRequest("PATCH", "/report", bytes.NewBuffer([]byte("{}")))
	response = executeRequest(req)
	assert.Equal(t, http.StatusMethodNotAllowed, response.Code)

	req, _ = http.NewRequest("DELETE", "/report", bytes.NewBuffer([]byte("{}")))
	response = executeRequest(req)
	assert.Equal(t, http.StatusMethodNotAllowed, response.Code)

	req, _ = http.NewRequest("HEAD", "/report", bytes.NewBuffer([]byte("{}")))
	response = executeRequest(req)
	assert.Equal(t, http.StatusMethodNotAllowed, response.Code)

	req, _ = http.NewRequest("OPTIONS", "/report", bytes.NewBuffer([]byte("{}")))
	response = executeRequest(req)
	assert.Equal(t, http.StatusMethodNotAllowed, response.Code)
}

func TestHandlerWithMalformedJSON(t *testing.T) {
	req, _ := http.NewRequest("POST", "/report", bytes.NewBuffer([]byte("{dsdsad")))
	response := executeRequest(req)
	assert.Equal(t, http.StatusInternalServerError, response.Code)

	req, _ = http.NewRequest("POST", "/report", bytes.NewBuffer([]byte("")))
	response = executeRequest(req)
	assert.Equal(t, http.StatusInternalServerError, response.Code)

	req, _ = http.NewRequest("POST", "/report", bytes.NewBuffer(nil))
	response = executeRequest(req)
	assert.Equal(t, http.StatusInternalServerError, response.Code)
}
