package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"panel/database"
)

type XrayManager interface {
	AddClient(protocol, email, credential string) error
	RemoveClient(protocol, email string) error
}

type TrafficResetter interface {
	ResetClient(id int64)
}

type ClientHandler struct {
	TunnelManager interface {
		VLESSURL() string
		TrojanURL() string
	}

	XrayManager     XrayManager
	TrafficResetter TrafficResetter
}

func NewClientHandler(
	tunnelManager interface {
		VLESSURL() string
		TrojanURL() string
	},
	xrayManager XrayManager,
	trafficResetter TrafficResetter,
) *ClientHandler {

	return &ClientHandler{
		TunnelManager:   tunnelManager,
		XrayManager:     xrayManager,
		TrafficResetter: trafficResetter,
	}
}

// dashboardRedirect redirects to the dashboard with a unique URL.
// This prevents the browser/proxy from reusing a previously rendered dashboard.
func dashboardRedirect(w http.ResponseWriter, r *http.Request) {
	redirectURL := "/?refresh=" + strconv.FormatInt(time.Now().UnixNano(), 10)
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

// Create creates a new client.
func (h *ClientHandler) Create(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	protocol := strings.TrimSpace(r.FormValue("protocol"))
	quotaValue := strings.TrimSpace(r.FormValue("quota"))

	if name == "" {
		http.Error(w, "client name is required", http.StatusBadRequest)
		return
	}

	if protocol != "vless" && protocol != "trojan" {
		http.Error(w, "invalid protocol", http.StatusBadRequest)
		return
	}

	trafficLimit, err := parseQuotaGB(quotaValue)
	if err != nil {
		http.Error(w, "invalid quota", http.StatusBadRequest)
		return
	}

	var clientUUID string
	var password string

	if protocol == "vless" {
		clientUUID = uuid.New().String()
	} else {
		password = generatePassword(24)
	}

	result, err := database.DB.Exec(`
		INSERT INTO clients
		(
			name,
			protocol,
			uuid,
			password,
			created_at,
			traffic_limit_bytes,
			traffic_used_bytes,
			enabled,
			last_seen
		)
		VALUES (?, ?, ?, ?, ?, ?, 0, 1, NULL)
	`,
		name,
		protocol,
		clientUUID,
		password,
		time.Now(),
		trafficLimit,
	)

	if err != nil {
		http.Error(w, "failed to create client", http.StatusInternalServerError)
		return
	}

	clientID, err := result.LastInsertId()
	if err != nil {
		http.Error(w, "failed to get created client id", http.StatusInternalServerError)
		return
	}

	if h.XrayManager != nil {
		credential := clientUUID
		if protocol == "trojan" {
			credential = password
		}

		email := fmt.Sprintf("client-%d", clientID)

		if err := h.XrayManager.AddClient(protocol, email, credential); err != nil {
			_, _ = database.DB.Exec(
				"DELETE FROM clients WHERE id = ?",
				clientID,
			)

			http.Error(
				w,
				"client was not added to Xray: "+err.Error(),
				http.StatusInternalServerError,
			)
			return
		}
	}

	dashboardRedirect(w, r)
}

// Delete deletes a client.
func (h *ClientHandler) Delete(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id, err := strconv.ParseInt(r.FormValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid client id", http.StatusBadRequest)
		return
	}

	var (
		protocol string
		uuid     string
		password string
		enabled  int
	)

	err = database.DB.QueryRow(`
		SELECT protocol, uuid, password, enabled
		FROM clients
		WHERE id = ?
	`, id).Scan(
		&protocol,
		&uuid,
		&password,
		&enabled,
	)

	if err != nil {
		http.Error(w, "client not found", http.StatusNotFound)
		return
	}

	email := fmt.Sprintf("client-%d", id)

	if enabled == 1 && h.XrayManager != nil {
		if err := h.XrayManager.RemoveClient(protocol, email); err != nil {
			http.Error(
				w,
				"client was not deleted because Xray update failed: "+err.Error(),
				http.StatusInternalServerError,
			)
			return
		}
	}

	_, err = database.DB.Exec(
		"DELETE FROM clients WHERE id = ?",
		id,
	)

	if err != nil {
		// Restore the client in Xray if the database deletion failed.
		if enabled == 1 && h.XrayManager != nil {
			credential := uuid
			if protocol == "trojan" {
				credential = password
			}
			_ = h.XrayManager.AddClient(protocol, email, credential)
		}

		http.Error(w, "failed to delete client", http.StatusInternalServerError)
		return
	}

	dashboardRedirect(w, r)
}

// EditName changes the name of a client.
func (h *ClientHandler) EditName(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id, err := strconv.ParseInt(r.FormValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid client id", http.StatusBadRequest)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))

	if name == "" {
		http.Error(w, "client name is required", http.StatusBadRequest)
		return
	}

	result, err := database.DB.Exec(`
		UPDATE clients
		SET name = ?
		WHERE id = ?
	`, name, id)

	if err != nil {
		http.Error(w, "failed to update client name", http.StatusInternalServerError)
		return
	}

	affected, err := result.RowsAffected()
	if err != nil {
		http.Error(w, "failed to update client name", http.StatusInternalServerError)
		return
	}

	if affected == 0 {
		http.Error(w, "client not found", http.StatusNotFound)
		return
	}

	// Client name is only stored in the database.
	// Xray uses client-ID as its stable email, so no Xray update is needed.
	dashboardRedirect(w, r)
}

// ChangeUUID changes the UUID of a VLESS client.
func (h *ClientHandler) ChangeUUID(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id, err := strconv.ParseInt(r.FormValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid client id", http.StatusBadRequest)
		return
	}

	var (
		protocol string
		oldUUID  string
		enabled  int
	)

	err = database.DB.QueryRow(`
		SELECT protocol, uuid, enabled
		FROM clients
		WHERE id = ?
	`, id).Scan(
		&protocol,
		&oldUUID,
		&enabled,
	)

	if err != nil {
		http.Error(w, "client not found", http.StatusNotFound)
		return
	}

	if protocol != "vless" {
		http.Error(w, "UUID can only be changed for VLESS clients", http.StatusBadRequest)
		return
	}

	newUUID := uuid.New().String()
	email := fmt.Sprintf("client-%d", id)

	// Remove the old account first.
	if enabled == 1 && h.XrayManager != nil {
		if err := h.XrayManager.RemoveClient("vless", email); err != nil {
			http.Error(
				w,
				"failed to remove old UUID from Xray: "+err.Error(),
				http.StatusInternalServerError,
			)
			return
		}
	}

	_, err = database.DB.Exec(`
		UPDATE clients
		SET uuid = ?
		WHERE id = ?
	`, newUUID, id)

	if err != nil {
		// Restore old account if database update failed.
		if enabled == 1 && h.XrayManager != nil {
			_ = h.XrayManager.AddClient("vless", email, oldUUID)
		}

		http.Error(w, "failed to change UUID", http.StatusInternalServerError)
		return
	}

	// Add the new account to the running Xray process.
	if enabled == 1 && h.XrayManager != nil {
		if err := h.XrayManager.AddClient("vless", email, newUUID); err != nil {

			_, _ = database.DB.Exec(`
				UPDATE clients
				SET uuid = ?
				WHERE id = ?
			`, oldUUID, id)

			_ = h.XrayManager.AddClient("vless", email, oldUUID)

			http.Error(
				w,
				"UUID was not changed in Xray: "+err.Error(),
				http.StatusInternalServerError,
			)
			return
		}
	}

	dashboardRedirect(w, r)
}

// ChangePassword changes the password of a Trojan client.
func (h *ClientHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id, err := strconv.ParseInt(r.FormValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid client id", http.StatusBadRequest)
		return
	}

	var (
		protocol     string
		oldPassword  string
		enabled      int
	)

	err = database.DB.QueryRow(`
		SELECT protocol, password, enabled
		FROM clients
		WHERE id = ?
	`, id).Scan(
		&protocol,
		&oldPassword,
		&enabled,
	)

	if err != nil {
		http.Error(w, "client not found", http.StatusNotFound)
		return
	}

	if protocol != "trojan" {
		http.Error(w, "password can only be changed for Trojan clients", http.StatusBadRequest)
		return
	}

	newPassword := generatePassword(24)
	email := fmt.Sprintf("client-%d", id)

	// Remove the old account first.
	if enabled == 1 && h.XrayManager != nil {
		if err := h.XrayManager.RemoveClient("trojan", email); err != nil {
			http.Error(
				w,
				"failed to remove old password from Xray: "+err.Error(),
				http.StatusInternalServerError,
			)
			return
		}
	}

	_, err = database.DB.Exec(`
		UPDATE clients
		SET password = ?
		WHERE id = ?
	`, newPassword, id)

	if err != nil {
		if enabled == 1 && h.XrayManager != nil {
			_ = h.XrayManager.AddClient("trojan", email, oldPassword)
		}

		http.Error(w, "failed to change password", http.StatusInternalServerError)
		return
	}

	// Add the new account to the running Xray process.
	if enabled == 1 && h.XrayManager != nil {
		if err := h.XrayManager.AddClient("trojan", email, newPassword); err != nil {

			_, _ = database.DB.Exec(`
				UPDATE clients
				SET password = ?
				WHERE id = ?
			`, oldPassword, id)

			_ = h.XrayManager.AddClient("trojan", email, oldPassword)

			http.Error(
				w,
				"password was not changed in Xray: "+err.Error(),
				http.StatusInternalServerError,
			)
			return
		}
	}

	dashboardRedirect(w, r)
}

// SetEnabled enables or disables a client.
func (h *ClientHandler) SetEnabled(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id, err := strconv.ParseInt(r.FormValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid client id", http.StatusBadRequest)
		return
	}

	action := strings.ToLower(strings.TrimSpace(r.FormValue("action")))

	var enabled int

	switch action {
	case "enable":
		enabled = 1

	case "disable":
		enabled = 0

	default:
		http.Error(w, "invalid action", http.StatusBadRequest)
		return
	}

	var (
		protocol     string
		clientUUID   string
		password     string
		oldEnabled   int
	)

	err = database.DB.QueryRow(`
		SELECT protocol, uuid, password, enabled
		FROM clients
		WHERE id = ?
	`, id).Scan(
		&protocol,
		&clientUUID,
		&password,
		&oldEnabled,
	)

	if err != nil {
		http.Error(w, "client not found", http.StatusNotFound)
		return
	}

	// Do not allow manually enabling a client whose quota is already reached.
	if enabled == 1 {

		var used int64
		var limit int64

		err = database.DB.QueryRow(`
			SELECT traffic_used_bytes, traffic_limit_bytes
			FROM clients
			WHERE id = ?
		`, id).Scan(&used, &limit)

		if err != nil {
			http.Error(w, "client not found", http.StatusNotFound)
			return
		}

		if limit > 0 && used >= limit {
			http.Error(
				w,
				"client has reached its traffic quota",
				http.StatusConflict,
			)
			return
		}
	}

	email := fmt.Sprintf("client-%d", id)

	// Only change Xray when the state actually changes.
	if oldEnabled != enabled && h.XrayManager != nil {

		if enabled == 1 {
			credential := clientUUID
			if protocol == "trojan" {
				credential = password
			}

			if err := h.XrayManager.AddClient(protocol, email, credential); err != nil {
				http.Error(
					w,
					"failed to enable client in Xray: "+err.Error(),
					http.StatusInternalServerError,
				)
				return
			}
		} else {
			if err := h.XrayManager.RemoveClient(protocol, email); err != nil {
				http.Error(
					w,
					"failed to disable client in Xray: "+err.Error(),
					http.StatusInternalServerError,
				)
				return
			}
		}
	}

	result, err := database.DB.Exec(`
		UPDATE clients
		SET enabled = ?
		WHERE id = ?
	`, enabled, id)

	if err != nil {
		// Restore Xray state if the database update failed.
		if oldEnabled != enabled && h.XrayManager != nil {

			if oldEnabled == 1 {
				credential := clientUUID
				if protocol == "trojan" {
					credential = password
				}
				_ = h.XrayManager.AddClient(protocol, email, credential)
			} else {
				_ = h.XrayManager.RemoveClient(protocol, email)
			}
		}

		http.Error(w, "failed to change client status", http.StatusInternalServerError)
		return
	}

	affected, err := result.RowsAffected()
	if err != nil {
		http.Error(w, "failed to change client status", http.StatusInternalServerError)
		return
	}

	if affected == 0 {
		http.Error(w, "client not found", http.StatusNotFound)
		return
	}

	dashboardRedirect(w, r)
}

// EditQuota changes the traffic quota of a client.
func (h *ClientHandler) EditQuota(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id, err := strconv.ParseInt(r.FormValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid client id", http.StatusBadRequest)
		return
	}

	quotaValue := strings.TrimSpace(r.FormValue("quota"))

	trafficLimit, err := parseQuotaGB(quotaValue)
	if err != nil {
		http.Error(w, "invalid quota", http.StatusBadRequest)
		return
	}

	var (
		trafficUsed int64
		protocol    string
		clientUUID  string
		password    string
		oldEnabled  int
		oldLimit    int64
	)

	err = database.DB.QueryRow(`
		SELECT
			traffic_used_bytes,
			protocol,
			uuid,
			password,
			enabled,
			traffic_limit_bytes
		FROM clients
		WHERE id = ?
	`, id).Scan(
		&trafficUsed,
		&protocol,
		&clientUUID,
		&password,
		&oldEnabled,
		&oldLimit,
	)

	if err != nil {
		http.Error(w, "client not found", http.StatusNotFound)
		return
	}

	newEnabled := 1

	if trafficLimit > 0 && trafficUsed >= trafficLimit {
		newEnabled = 0
	}

	email := fmt.Sprintf("client-%d", id)

	_, err = database.DB.Exec(`
		UPDATE clients
		SET traffic_limit_bytes = ?,
		    enabled = ?
		WHERE id = ?
	`,
		trafficLimit,
		newEnabled,
		id,
	)

	if err != nil {
		http.Error(w, "failed to update quota", http.StatusInternalServerError)
		return
	}

	// If the quota change changes the enabled state,
	// update the running Xray process without restarting it.
	if oldEnabled != newEnabled && h.XrayManager != nil {

		if newEnabled == 1 {
			credential := clientUUID
			if protocol == "trojan" {
				credential = password
			}

			if err := h.XrayManager.AddClient(protocol, email, credential); err != nil {

				_, _ = database.DB.Exec(`
					UPDATE clients
					SET traffic_limit_bytes = ?,
					    enabled = ?
					WHERE id = ?
				`, oldLimit, oldEnabled, id)

				http.Error(
					w,
					"quota was updated but Xray could not enable client: "+err.Error(),
					http.StatusInternalServerError,
				)
				return
			}
		} else {
			if err := h.XrayManager.RemoveClient(protocol, email); err != nil {

				_, _ = database.DB.Exec(`
					UPDATE clients
					SET traffic_limit_bytes = ?,
					    enabled = ?
					WHERE id = ?
				`, oldLimit, oldEnabled, id)

				http.Error(
					w,
					"quota was updated but Xray could not disable client: "+err.Error(),
					http.StatusInternalServerError,
				)
				return
			}
		}
	}

	dashboardRedirect(w, r)
}

// ResetTraffic resets the accumulated traffic of a client.
func (h *ClientHandler) ResetTraffic(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id, err := strconv.ParseInt(r.FormValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid client id", http.StatusBadRequest)
		return
	}

	var (
		protocol   string
		clientUUID string
		password   string
		oldEnabled int
	)

	err = database.DB.QueryRow(`
		SELECT protocol, uuid, password, enabled
		FROM clients
		WHERE id = ?
	`, id).Scan(
		&protocol,
		&clientUUID,
		&password,
		&oldEnabled,
	)

	if err != nil {
		http.Error(w, "client not found", http.StatusNotFound)
		return
	}

	email := fmt.Sprintf("client-%d", id)

	_, err = database.DB.Exec(`
		UPDATE clients
		SET traffic_used_bytes = 0,
		    last_seen = NULL,
		    enabled = 1
		WHERE id = ?
	`, id)

	if err != nil {
		http.Error(w, "failed to reset traffic", http.StatusInternalServerError)
		return
	}

	// ResetTraffic always enables the client.
	if oldEnabled == 0 && h.XrayManager != nil {

		credential := clientUUID
		if protocol == "trojan" {
			credential = password
		}

		if err := h.XrayManager.AddClient(protocol, email, credential); err != nil {

			_, _ = database.DB.Exec(`
				UPDATE clients
				SET enabled = ?
				WHERE id = ?
			`, oldEnabled, id)

			http.Error(
				w,
				"traffic was reset but Xray could not enable client: "+err.Error(),
				http.StatusInternalServerError,
			)
			return
		}
	}

	if h.TrafficResetter != nil {
		h.TrafficResetter.ResetClient(id)
	}

	dashboardRedirect(w, r)
}

// Config generates the VLESS/Trojan configuration.
func (h *ClientHandler) Config(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid client id", http.StatusBadRequest)
		return
	}

	var (
		name       string
		protocol   string
		clientUUID string
		password   string
		enabled    int
	)

	err = database.DB.QueryRow(`
		SELECT
			name,
			protocol,
			uuid,
			password,
			enabled
		FROM clients
		WHERE id = ?
	`, id).Scan(
		&name,
		&protocol,
		&clientUUID,
		&password,
		&enabled,
	)

	if err != nil {
		http.Error(w, "client not found", http.StatusNotFound)
		return
	}

	if enabled == 0 {
		http.Error(w, "client is disabled", http.StatusForbidden)
		return
	}

	if h.TunnelManager == nil {
		http.Error(
			w,
			"tunnel manager unavailable",
			http.StatusServiceUnavailable,
		)
		return
	}

	var tunnelURL string

	if protocol == "vless" {
		tunnelURL = h.TunnelManager.VLESSURL()
	} else {
		tunnelURL = h.TunnelManager.TrojanURL()
	}

	if tunnelURL == "" {
		http.Error(
			w,
			"tunnel is not ready yet",
			http.StatusServiceUnavailable,
		)
		return
	}

	parsedURL, err := url.Parse(tunnelURL)
	if err != nil {
		http.Error(
			w,
			"invalid tunnel URL",
			http.StatusInternalServerError,
		)
		return
	}

	host := parsedURL.Host

	var result string

	if protocol == "vless" {

		result = fmt.Sprintf(
			"vless://%s@%s:443?encryption=none&security=tls&type=ws&host=%s&path=%s&sni=%s#%s",
			clientUUID,
			host,
			url.QueryEscape(host),
			url.QueryEscape("/vless"),
			url.QueryEscape(host),
			url.QueryEscape(name),
		)

	} else {

		result = fmt.Sprintf(
			"trojan://%s@%s:443?security=tls&type=ws&host=%s&path=%s&sni=%s#%s",
			url.QueryEscape(password),
			host,
			url.QueryEscape(host),
			url.QueryEscape("/trojan"),
			url.QueryEscape(host),
			url.QueryEscape(name),
		)
	}

	w.Header().Set(
		"Content-Type",
		"text/plain; charset=utf-8",
	)

	_, _ = w.Write([]byte(result))
}

func parseQuotaGB(value string) (int64, error) {

	if value == "" {
		return 0, nil
	}

	gb, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0, err
	}

	if gb < 0 {
		return 0, fmt.Errorf("quota cannot be negative")
	}

	const bytesPerGB = 1000000000.0

	bytes := gb * bytesPerGB

	if bytes > float64(^uint64(0)>>1) {
		return 0, fmt.Errorf("quota is too large")
	}

	return int64(bytes), nil
}

func generatePassword(length int) string {

	b := make([]byte, length)

	if _, err := rand.Read(b); err != nil {
		return uuid.New().String()
	}

	return hex.EncodeToString(b)[:length]
}
