// +build !nometrics

// Package metrics provides Prometheus metrics support
package metrics

import (
	"github.com/go-chi/chi"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/drakkan/sftpgo/version"
)

const (
	loginMethodPublicKey           = "publickey"
	loginMethodKeyboardInteractive = "keyboard-interactive"
	loginMethodKeyAndPassword      = "publickey+password"
	loginMethodKeyAndKeyboardInt   = "publickey+keyboard-interactive"
)

func init() {
	version.AddFeature("+metrics")
}

var (
	// dataproviderAvailability is the metric that reports the availability for the configured data provider
	dataproviderAvailability = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "sftpgo_dataprovider_availability",
		Help: "Availability for the configured data provider, 1 means OK, 0 KO",
	})

	// activeConnections is the metric that reports the total number of active connections
	activeConnections = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "sftpgo_active_connections",
		Help: "Total number of logged in users",
	})

	// totalUploads is the metric that reports the total number of successful uploads
	totalUploads = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_uploads_total",
		Help: "The total number of successful uploads",
	})

	// totalDownloads is the metric that reports the total number of successful downloads
	totalDownloads = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_downloads_total",
		Help: "The total number of successful downloads",
	})

	// totalUploadErrors is the metric that reports the total number of upload errors
	totalUploadErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_upload_errors_total",
		Help: "The total number of upload errors",
	})

	// totalDownloadErrors is the metric that reports the total number of download errors
	totalDownloadErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_download_errors_total",
		Help: "The total number of download errors",
	})

	// totalUploadSize is the metric that reports the total uploads size as bytes
	totalUploadSize = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_upload_size",
		Help: "The total upload size as bytes, partial uploads are included",
	})

	// totalDownloadSize is the metric that reports the total downloads size as bytes
	totalDownloadSize = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_download_size",
		Help: "The total download size as bytes, partial downloads are included",
	})

	// totalSSHCommands is the metric that reports the total number of executed SSH commands
	totalSSHCommands = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_ssh_commands_total",
		Help: "The total number of executed SSH commands",
	})

	// totalSSHCommandErrors is the metric that reports the total number of SSH command errors
	totalSSHCommandErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_ssh_command_errors_total",
		Help: "The total number of SSH command errors",
	})

	// totalLoginAttempts is the metric that reports the total number of login attempts
	totalLoginAttempts = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_login_attempts_total",
		Help: "The total number of login attempts",
	})

	// totalNoAuthTryed is te metric that reports the total number of clients disconnected
	// for inactivity before trying to login
	totalNoAuthTryed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_no_auth_total",
		Help: "The total number of clients disconnected for inactivity before trying to login",
	})

	// totalLoginOK is the metric that reports the total number of successful logins
	totalLoginOK = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_login_ok_total",
		Help: "The total number of successful logins",
	})

	// totalLoginFailed is the metric that reports the total number of failed logins
	totalLoginFailed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_login_ko_total",
		Help: "The total number of failed logins",
	})

	// totalPasswordLoginAttempts is the metric that reports the total number of login attempts
	// using a password
	totalPasswordLoginAttempts = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_password_login_attempts_total",
		Help: "The total number of login attempts using a password",
	})

	// totalPasswordLoginOK is the metric that reports the total number of successful logins
	// using a password
	totalPasswordLoginOK = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_password_login_ok_total",
		Help: "The total number of successful logins using a password",
	})

	// totalPasswordLoginFailed is the metric that reports the total number of failed logins
	// using a password
	totalPasswordLoginFailed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_password_login_ko_total",
		Help: "The total number of failed logins using a password",
	})

	// totalKeyLoginAttempts is the metric that reports the total number of login attempts
	// using a public key
	totalKeyLoginAttempts = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_public_key_login_attempts_total",
		Help: "The total number of login attempts using a public key",
	})

	// totalKeyLoginOK is the metric that reports the total number of successful logins
	// using a public key
	totalKeyLoginOK = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_public_key_login_ok_total",
		Help: "The total number of successful logins using a public key",
	})

	// totalKeyLoginFailed is the metric that reports the total number of failed logins
	// using a public key
	totalKeyLoginFailed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_public_key_login_ko_total",
		Help: "The total number of failed logins using a public key",
	})

	// totalInteractiveLoginAttempts is the metric that reports the total number of login attempts
	// using keyboard interactive authentication
	totalInteractiveLoginAttempts = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_keyboard_interactive_login_attempts_total",
		Help: "The total number of login attempts using keyboard interactive authentication",
	})

	// totalInteractiveLoginOK is the metric that reports the total number of successful logins
	// using keyboard interactive authentication
	totalInteractiveLoginOK = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_keyboard_interactive_login_ok_total",
		Help: "The total number of successful logins using keyboard interactive authentication",
	})

	// totalInteractiveLoginFailed is the metric that reports the total number of failed logins
	// using keyboard interactive authentication
	totalInteractiveLoginFailed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_keyboard_interactive_login_ko_total",
		Help: "The total number of failed logins using keyboard interactive authentication",
	})

	// totalKeyAndPasswordLoginAttempts is the metric that reports the total number of
	// login attempts using public key + password multi steps auth
	totalKeyAndPasswordLoginAttempts = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_key_and_password_login_attempts_total",
		Help: "The total number of login attempts using public key + password",
	})

	// totalKeyAndPasswordLoginOK is the metric that reports the total number of
	// successful logins using public key + password multi steps auth
	totalKeyAndPasswordLoginOK = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_key_and_password_login_ok_total",
		Help: "The total number of successful logins using public key + password",
	})

	// totalKeyAndPasswordLoginFailed is the metric that reports the total number of
	// failed logins using public key + password multi steps auth
	totalKeyAndPasswordLoginFailed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_key_and_password_login_ko_total",
		Help: "The total number of failed logins using  public key + password",
	})

	// totalKeyAndKeyIntLoginAttempts is the metric that reports the total number of
	// login attempts using public key + keyboard interactive multi steps auth
	totalKeyAndKeyIntLoginAttempts = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_key_and_keyboard_int_login_attempts_total",
		Help: "The total number of login attempts using public key + keyboard interactive",
	})

	// totalKeyAndKeyIntLoginOK is the metric that reports the total number of
	// successful logins using public key + keyboard interactive multi steps auth
	totalKeyAndKeyIntLoginOK = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_key_and_keyboard_int_login_ok_total",
		Help: "The total number of successful logins using public key + keyboard interactive",
	})

	// totalKeyAndKeyIntLoginFailed is the metric that reports the total number of
	// failed logins using public key + keyboard interactive multi steps auth
	totalKeyAndKeyIntLoginFailed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_key_and_keyboard_int_login_ko_total",
		Help: "The total number of failed logins using  public key + keyboard interactive",
	})

	totalHTTPRequests = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_http_req_total",
		Help: "The total number of HTTP requests served",
	})

	totalHTTPOK = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_http_req_ok_total",
		Help: "The total number of HTTP requests served with 2xx status code",
	})

	totalHTTPClientErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_http_client_errors_total",
		Help: "The total number of HTTP requests served with 4xx status code",
	})

	totalHTTPServerErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sftpgo_http_server_errors_total",
		Help: "The total number of HTTP requests served with 5xx status code",
	})
)

// AddMetricsEndpoint exposes metrics to the specified endpoint
func AddMetricsEndpoint(metricsPath string, handler chi.Router) {
	handler.Handle(metricsPath, promhttp.Handler())
}

// TransferCompleted updates metrics after an upload or a download
func TransferCompleted(bytesSent, bytesReceived int64, transferKind int, err error) {
	if transferKind == 0 {
		// upload
		if err == nil {
			totalUploads.Inc()
		} else {
			totalUploadErrors.Inc()
		}
		totalUploadSize.Add(float64(bytesReceived))
	} else {
		// download
		if err == nil {
			totalDownloads.Inc()
		} else {
			totalDownloadErrors.Inc()
		}
		totalDownloadSize.Add(float64(bytesSent))
	}
}

// SSHCommandCompleted update metrics after an SSH command terminates
func SSHCommandCompleted(err error) {
	if err == nil {
		totalSSHCommands.Inc()
	} else {
		totalSSHCommandErrors.Inc()
	}
}

// UpdateDataProviderAvailability updates the metric for the data provider availability
func UpdateDataProviderAvailability(err error) {
	if err == nil {
		dataproviderAvailability.Set(1)
	} else {
		dataproviderAvailability.Set(0)
	}
}

// AddLoginAttempt increments the metrics for login attempts
func AddLoginAttempt(authMethod string) {
	totalLoginAttempts.Inc()
	switch authMethod {
	case loginMethodPublicKey:
		totalKeyLoginAttempts.Inc()
	case loginMethodKeyboardInteractive:
		totalInteractiveLoginAttempts.Inc()
	case loginMethodKeyAndPassword:
		totalKeyAndPasswordLoginAttempts.Inc()
	case loginMethodKeyAndKeyboardInt:
		totalKeyAndKeyIntLoginAttempts.Inc()
	default:
		totalPasswordLoginAttempts.Inc()
	}
}

// AddLoginResult increments the metrics for login results
func AddLoginResult(authMethod string, err error) {
	if err == nil {
		totalLoginOK.Inc()
		switch authMethod {
		case loginMethodPublicKey:
			totalKeyLoginOK.Inc()
		case loginMethodKeyboardInteractive:
			totalInteractiveLoginOK.Inc()
		case loginMethodKeyAndPassword:
			totalKeyAndPasswordLoginOK.Inc()
		case loginMethodKeyAndKeyboardInt:
			totalKeyAndKeyIntLoginOK.Inc()
		default:
			totalPasswordLoginOK.Inc()
		}
	} else {
		totalLoginFailed.Inc()
		switch authMethod {
		case loginMethodPublicKey:
			totalKeyLoginFailed.Inc()
		case loginMethodKeyboardInteractive:
			totalInteractiveLoginFailed.Inc()
		case loginMethodKeyAndPassword:
			totalKeyAndPasswordLoginFailed.Inc()
		case loginMethodKeyAndKeyboardInt:
			totalKeyAndKeyIntLoginFailed.Inc()
		default:
			totalPasswordLoginFailed.Inc()
		}
	}
}

// AddNoAuthTryed increments the metric for clients disconnected
// for inactivity before trying to login
func AddNoAuthTryed() {
	totalNoAuthTryed.Inc()
}

// HTTPRequestServed increments the metrics for HTTP requests
func HTTPRequestServed(status int) {
	totalHTTPRequests.Inc()
	if status >= 200 && status < 300 {
		totalHTTPOK.Inc()
	} else if status >= 400 && status < 500 {
		totalHTTPClientErrors.Inc()
	} else if status >= 500 {
		totalHTTPServerErrors.Inc()
	}
}

// UpdateActiveConnectionsSize sets the metric for active connections
func UpdateActiveConnectionsSize(size int) {
	activeConnections.Set(float64(size))
}
