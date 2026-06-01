package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"cpa-control-center/internal/backend"
)

//go:embed all:public
var publicAssets embed.FS

type eventEnvelope struct {
	Event   string `json:"event"`
	Payload any    `json:"payload"`
}

type eventHub struct {
	mu      sync.Mutex
	nextID  int
	clients map[int]chan eventEnvelope
}

func newEventHub() *eventHub {
	return &eventHub{clients: make(map[int]chan eventEnvelope)}
}

func (h *eventHub) Emit(event string, payload any) {
	h.mu.Lock()
	defer h.mu.Unlock()

	message := eventEnvelope{Event: event, Payload: payload}
	for _, ch := range h.clients {
		select {
		case ch <- message:
		default:
		}
	}
}

func (h *eventHub) subscribe() (int, <-chan eventEnvelope) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.nextID++
	id := h.nextID
	ch := make(chan eventEnvelope, 64)
	h.clients[id] = ch
	return id, ch
}

func (h *eventHub) unsubscribe(id int) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if ch, ok := h.clients[id]; ok {
		delete(h.clients, id)
		close(ch)
	}
}

type apiServer struct {
	backend *backend.Backend
	events  *eventHub
}

type apiRequest struct {
	Args []json.RawMessage `json:"args"`
}

type apiResponse struct {
	Result any    `json:"result,omitempty"`
	Error  string `json:"error,omitempty"`
}

func main() {
	addr := envString("CPA_CONTROL_CENTER_ADDR", ":8080")
	dataDir := envString("CPA_CONTROL_CENTER_DATA_DIR", "/data")

	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		log.Fatalf("create data dir: %v", err)
	}

	hub := newEventHub()
	service, err := backend.New(dataDir, hub)
	if err != nil {
		log.Fatalf("start backend: %v", err)
	}
	defer func() {
		if err := service.Close(); err != nil {
			log.Printf("close backend: %v", err)
		}
	}()

	api := &apiServer{backend: service, events: hub}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/wails/{method}", api.handleWailsCall)
	mux.HandleFunc("GET /api/events", api.handleEvents)
	mux.HandleFunc("POST /api/log", handleBrowserLog)
	mux.HandleFunc("/", spaHandler())

	server := &http.Server{
		Addr:              addr,
		Handler:           basicAuth(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("CPA Control Center web server listening on %s", addr)
		errCh <- server.ListenAndServe()
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("serve: %v", err)
		}
	case <-stop:
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("shutdown: %v", err)
		}
	}
}

func (s *apiServer) handleWailsCall(w http.ResponseWriter, r *http.Request) {
	var request apiRequest
	if r.Body != nil {
		defer r.Body.Close()
		if err := json.NewDecoder(io.LimitReader(r.Body, 10<<20)).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
			writeAPIError(w, http.StatusBadRequest, err)
			return
		}
	}

	result, err := s.dispatch(r.PathValue("method"), request.Args)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusOK, apiResponse{Result: result})
}

func (s *apiServer) dispatch(method string, args []json.RawMessage) (any, error) {
	switch method {
	case "GetSettings":
		return s.backend.GetSettings()
	case "SaveSettings":
		var input backend.AppSettings
		if err := decodeArg(args, 0, &input); err != nil {
			return nil, err
		}
		return s.backend.SaveSettings(input)
	case "TestConnection":
		var input backend.AppSettings
		if err := decodeArg(args, 0, &input); err != nil {
			return nil, err
		}
		return s.backend.TestConnection(input)
	case "TestAndSaveSettings":
		var input backend.AppSettings
		if err := decodeArg(args, 0, &input); err != nil {
			return nil, err
		}
		return s.backend.TestAndSaveSettings(input)
	case "SyncInventory":
		return s.backend.SyncInventory()
	case "GetSchedulerStatus":
		return s.backend.GetSchedulerStatus(), nil
	case "GetDashboardSummary":
		return s.backend.GetDashboardSummary()
	case "GetDashboardSnapshot":
		return s.backend.GetDashboardSnapshot()
	case "GetCodexQuotaSnapshot":
		return s.backend.GetCodexQuotaSnapshot()
	case "GetCachedCodexQuotaSnapshot":
		return s.backend.GetCachedCodexQuotaSnapshot()
	case "ListAccounts":
		var filter backend.AccountFilter
		if err := decodeArg(args, 0, &filter); err != nil {
			return nil, err
		}
		return s.backend.ListAccounts(filter)
	case "ListAccountsPage":
		var filter backend.AccountFilter
		var page int
		var pageSize int
		if err := decodeArg(args, 0, &filter); err != nil {
			return nil, err
		}
		if err := decodeArg(args, 1, &page); err != nil {
			return nil, err
		}
		if err := decodeArg(args, 2, &pageSize); err != nil {
			return nil, err
		}
		return s.backend.ListAccountsPage(filter, page, pageSize)
	case "RunScan":
		return s.backend.RunScan()
	case "CancelScan":
		return s.backend.CancelScan()
	case "RunMaintain":
		var options backend.MaintainOptions
		if err := decodeArg(args, 0, &options); err != nil {
			return nil, err
		}
		return s.backend.RunMaintain(options)
	case "ProbeAccount":
		var name string
		if err := decodeArg(args, 0, &name); err != nil {
			return nil, err
		}
		return s.backend.ProbeAccount(name)
	case "ProbeAccounts":
		var names []string
		if err := decodeArg(args, 0, &names); err != nil {
			return nil, err
		}
		return s.backend.ProbeAccounts(names)
	case "SetAccountDisabled":
		var name string
		var disabled bool
		if err := decodeArg(args, 0, &name); err != nil {
			return nil, err
		}
		if err := decodeArg(args, 1, &disabled); err != nil {
			return nil, err
		}
		return s.backend.SetAccountDisabled(name, disabled)
	case "SetAccountsDisabled":
		var names []string
		var disabled bool
		if err := decodeArg(args, 0, &names); err != nil {
			return nil, err
		}
		if err := decodeArg(args, 1, &disabled); err != nil {
			return nil, err
		}
		return s.backend.SetAccountsDisabled(names, disabled)
	case "DeleteAccount":
		var name string
		if err := decodeArg(args, 0, &name); err != nil {
			return nil, err
		}
		return s.backend.DeleteAccount(name)
	case "DeleteAccounts":
		var names []string
		if err := decodeArg(args, 0, &names); err != nil {
			return nil, err
		}
		return s.backend.DeleteAccounts(names)
	case "ExportAccounts":
		var kind string
		var format string
		var exportPath string
		if err := decodeArg(args, 0, &kind); err != nil {
			return nil, err
		}
		if err := decodeArg(args, 1, &format); err != nil {
			return nil, err
		}
		if err := decodeArg(args, 2, &exportPath); err != nil {
			return nil, err
		}
		return s.backend.ExportAccounts(kind, format, exportPath)
	case "ExportAccountsDownload":
		var kind string
		var format string
		if err := decodeArg(args, 0, &kind); err != nil {
			return nil, err
		}
		if err := decodeArg(args, 1, &format); err != nil {
			return nil, err
		}
		return s.backend.ExportAccountsDownload(kind, format)
	case "ListScanHistory":
		var limit int
		if err := decodeArg(args, 0, &limit); err != nil {
			return nil, err
		}
		return s.backend.ListScanHistory(limit)
	case "GetScanDetails":
		runID, err := decodeInt64Arg(args, 0)
		if err != nil {
			return nil, err
		}
		return s.backend.GetScanDetails(runID)
	case "GetScanDetailsPage":
		runID, err := decodeInt64Arg(args, 0)
		if err != nil {
			return nil, err
		}
		var page int
		var pageSize int
		if err := decodeArg(args, 1, &page); err != nil {
			return nil, err
		}
		if err := decodeArg(args, 2, &pageSize); err != nil {
			return nil, err
		}
		return s.backend.GetScanDetailsPage(runID, page, pageSize)
	default:
		return nil, fmt.Errorf("unknown method %q", method)
	}
}

func (s *apiServer) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeAPIError(w, http.StatusInternalServerError, errors.New("streaming is not supported"))
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	id, events := s.events.subscribe()
	defer s.events.unsubscribe(id)

	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case event, ok := <-events:
			if !ok {
				return
			}
			data, err := json.Marshal(event)
			if err != nil {
				continue
			}
			_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-ticker.C:
			_, _ = fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func handleBrowserLog(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Level   string `json:"level"`
		Message string `json:"message"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&payload)
	if payload.Message != "" {
		log.Printf("browser %s: %s", payload.Level, payload.Message)
	}
	writeJSON(w, http.StatusOK, apiResponse{Result: true})
}

func decodeArg(args []json.RawMessage, index int, target any) error {
	if index >= len(args) {
		return fmt.Errorf("missing argument %d", index)
	}
	if len(args[index]) == 0 || string(args[index]) == "null" {
		return nil
	}
	return json.Unmarshal(args[index], target)
}

func decodeInt64Arg(args []json.RawMessage, index int) (int64, error) {
	if index >= len(args) {
		return 0, fmt.Errorf("missing argument %d", index)
	}

	var number json.Number
	if err := json.Unmarshal(args[index], &number); err == nil {
		return strconv.ParseInt(number.String(), 10, 64)
	}

	var value int64
	if err := json.Unmarshal(args[index], &value); err != nil {
		return 0, err
	}
	return value, nil
}

func spaHandler() http.HandlerFunc {
	subFS, err := fs.Sub(publicAssets, "public")
	if err != nil {
		panic(err)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if name == "." || name == "" {
			name = "index.html"
		}
		if _, err := fs.Stat(subFS, name); err != nil {
			name = "index.html"
		}
		http.ServeFileFS(w, r, subFS, name)
	}
}

const controlSessionCookieName = "cpa_control_session"

func basicAuth(next http.Handler) http.Handler {
	username := os.Getenv("CPA_CONTROL_CENTER_USERNAME")
	password := os.Getenv("CPA_CONTROL_CENTER_PASSWORD")
	if username == "" && password == "" {
		return next
	}

	realm := `Basic realm="CPA Control Center"`
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if validControlSessionCookie(r, username, password) {
			next.ServeHTTP(w, r)
			return
		}

		user, pass, ok := r.BasicAuth()
		if !ok ||
			subtle.ConstantTimeCompare([]byte(user), []byte(username)) != 1 ||
			subtle.ConstantTimeCompare([]byte(pass), []byte(password)) != 1 {
			w.Header().Set("WWW-Authenticate", realm)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		setControlSessionCookie(w, r, username, password)
		next.ServeHTTP(w, r)
	})
}

func validControlSessionCookie(r *http.Request, username string, password string) bool {
	cookie, err := r.Cookie(controlSessionCookieName)
	if err != nil || cookie.Value == "" {
		return false
	}
	parts := strings.Split(cookie.Value, ":")
	if len(parts) != 2 {
		return false
	}
	expiresUnix, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || time.Now().Unix() > expiresUnix {
		return false
	}
	expected := signControlSession(username, password, expiresUnix)
	return subtle.ConstantTimeCompare([]byte(parts[1]), []byte(expected)) == 1
}

func setControlSessionCookie(w http.ResponseWriter, r *http.Request, username string, password string) {
	days := envInt("CPA_CONTROL_CENTER_SESSION_DAYS", 90)
	if days <= 0 {
		days = 90
	}
	expires := time.Now().Add(time.Duration(days) * 24 * time.Hour)
	expiresUnix := expires.Unix()
	http.SetCookie(w, &http.Cookie{
		Name:     controlSessionCookieName,
		Value:    fmt.Sprintf("%d:%s", expiresUnix, signControlSession(username, password, expiresUnix)),
		Path:     "/",
		Expires:  expires,
		MaxAge:   int(time.Until(expires).Seconds()),
		HttpOnly: true,
		Secure:   isHTTPSRequest(r),
		SameSite: http.SameSiteLaxMode,
	})
}

func signControlSession(username string, password string, expiresUnix int64) string {
	mac := hmac.New(sha256.New, []byte(password))
	_, _ = mac.Write([]byte(fmt.Sprintf("%s:%d", username, expiresUnix)))
	return hex.EncodeToString(mac.Sum(nil))
}

func isHTTPSRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func writeAPIError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, apiResponse{Error: err.Error()})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func envString(key string, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func envInt(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}
