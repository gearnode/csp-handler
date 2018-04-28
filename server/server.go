package server

import (
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"

	"encoding/json"
	"net/http"
	"os"
)

// CSP represent the root node of the CSP violation event.
type CSP struct {
	Report Report `json:"csp-report"`
}

// Report represent the informations about the CSP violation event.
type Report struct {
	DocumentURI       string `json:"document-uri"`
	Referrer          string `json:"referrer"`
	ViolatedDirective string `json:"violated-directive"`
	OriginalPolicy    string `json:"original-policy"`
	BlockedURI        string `json:"blocked-uri"`
}

// App represent the application and there dependencies.
type App struct {
	Router *mux.Router
	Logger *logrus.Logger
}

// Initialize create the HTTP router and create the elasticsearch index if needed.
func (a *App) Initialize() {
	a.Logger = logrus.New()
	a.Logger.Formatter = &logrus.JSONFormatter{}
	a.Logger.Out = os.Stdout

	a.Router = mux.NewRouter()

	a.initializeRoutes()
}

// Run start the HTTP server with the given addr.
func (a *App) Run(addr string) {
	a.Logger.WithFields(logrus.Fields{"addr": addr}).Info("starting http server")
	a.Logger.Fatal(http.ListenAndServe(addr, a.Router))
}

func (a *App) initializeRoutes() {
	a.Router.HandleFunc("/report", a.cspHandler).Methods("POST")
}

func init() {
}

func (a *App) cspHandler(w http.ResponseWriter, r *http.Request) {
	csp := CSP{}

	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&csp); err != nil {
		a.Logger.WithFields(logrus.Fields{"error": err.Error()}).Error("decode json payload failed")
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	a.Logger.WithFields(logrus.Fields{
		"document-uri":       csp.Report.DocumentURI,
		"referrer":           csp.Report.Referrer,
		"violated-directive": csp.Report.ViolatedDirective,
		"original-policy":    csp.Report.OriginalPolicy,
		"blocked-uri":        csp.Report.BlockedURI,
	}).Info("new content security policy violation received")

	w.WriteHeader(http.StatusOK)
}
