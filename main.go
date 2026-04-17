package main

// NOTE: vibe coded by itewk@redhat.com with gemini.google.com

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"go.yaml.in/yaml/v2"
)

// TokenReview matches the Kubernetes authentication.k8s.io/v1 TokenReview type.
type TokenReview struct {
	APIVersion string             `json:"apiVersion"`
	Kind       string             `json:"kind"`
	Spec       TokenReviewSpec    `json:"spec"`
	Status     *TokenReviewStatus `json:"status,omitempty"`
}

type TokenReviewSpec struct {
	Token string `json:"token"`
}

type TokenReviewStatus struct {
	Authenticated bool      `json:"authenticated"`
	User          *UserInfo `json:"user,omitempty"`
	Error         string    `json:"error,omitempty"`
}

type UserInfo struct {
	Username string              `json:"username"`
	UID      string              `json:"uid"`
	Groups   []string            `json:"groups,omitempty"`
	Extra    map[string][]string `json:"extra,omitempty"`
}

// https://kubernetes.io/docs/reference/config-api/kubeconfig.v1/
type KubeConfig struct {
	APIVersion     string         `yaml:"apiVersion"`
	Kind           string         `yaml:"kind"`
	Clusters       []NamedCluster `yaml:"clusters"`
	Users          []NamedUser    `yaml:"users"`
	Contexts       []NamedContext `yaml:"contexts"`
	CurrentContext string         `yaml:"current-context"`
}

type NamedCluster struct {
	Name    string `yaml:"name"`
	Cluster struct {
		Server                   string `yaml:"server"`
		CertificateAuthorityData string `yaml:"certificate-authority-data"`
		TLSServerName            string `yaml:"tls-server-name"`
	} `yaml:"cluster"`
}

type NamedUser struct {
	Name string `yaml:"name"`
	User struct {
		Token                 string `yaml:"token"`
		ClientCertificateData string `yaml:"client-certificate-data"`
		ClientKeyData         string `yaml:"client-key-data"`
	} `yaml:"user"`
}

type NamedContext struct {
	Name    string `yaml:"name"`
	Context struct {
		Cluster string `yaml:"cluster"`
		User    string `yaml:"user"`
	} `yaml:"context"`
}

// parsed from supplied kubeConfig files
type UpstreamWebhookTarget struct {
	Server    string
	TLSConfig *tls.Config
}

type webhookHandler struct {
	openShiftWebhookTarget *UpstreamWebhookTarget
	externalWebhookTarget  *UpstreamWebhookTarget
}

// serve runs the webhook HTTPS server.
func serve(tlsCert, tlsKey, addr, openShiftWebhookKubeConfigPath string, externalWebhookKubeConfigPath string) error {

	// 1. Pre-load and Parse OpenShift Config
	openShiftWebhookTarget, err := parseUpstreamWebhookKubeConfig(openShiftWebhookKubeConfigPath)
	if err != nil {
		return fmt.Errorf("failed to parse OpenShift Internal Oauth upstream webhook KubeConfig: %w", err)
	}

	// 2. Pre-load and Parse External Config
	externalWebhookTarget, err := parseUpstreamWebhookKubeConfig(externalWebhookKubeConfigPath)
	if err != nil {
		return fmt.Errorf("failed to parse external upstream webhook KubeConfig: %w", err)
	}

	mux := http.NewServeMux()

	// Register the health check endpoint
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	// Register the main webhook handler with the config paths
	handler := &webhookHandler{
		openShiftWebhookTarget: openShiftWebhookTarget,
		externalWebhookTarget:  externalWebhookTarget,
	}
	mux.Handle("/", handler)

	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	slog.Info("Starting multiplexer-proxy-webhook", "server-address", addr)
	return server.ListenAndServeTLS(tlsCert, tlsKey)
}

func parseUpstreamWebhookKubeConfig(path string) (*UpstreamWebhookTarget, error) {
	cfg, err := loadKubeConfig(path)
	if err != nil {
		return nil, err
	}

	cluster, err := getClusterByCurrentContext(*cfg)
	if err != nil {
		return nil, err
	}

	user, err := getUserByCurrentContext(*cfg)
	if err != nil {
		return nil, err
	}

	tlsCfg, err := createTLSConfig(
		cluster.Cluster.TLSServerName,
		cluster.Cluster.CertificateAuthorityData,
		user.User.ClientCertificateData,
		user.User.ClientKeyData,
	)
	if err != nil {
		return nil, err
	}

	return &UpstreamWebhookTarget{
		Server:    cluster.Cluster.Server,
		TLSConfig: tlsCfg,
	}, nil
}

func (h *webhookHandler) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		slog.Error("method not allowed", "method", request.Method)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(request.Body)
	if err != nil {
		slog.Error("failed reading request body", "error", err)
		http.Error(w, "failed reading request body", http.StatusBadRequest)
		return
	}
	defer request.Body.Close()

	var review TokenReview
	if err := json.Unmarshal(body, &review); err != nil {
		slog.Error("failed parsing TokenReview", "error", err)
		http.Error(w, "failed parsing TokenReview", http.StatusBadRequest)
		return
	}

	if review.Spec.Token == "" {
		slog.Error("Empty token in TokenReview")
		http.Error(w, "Empty token in TokenReview", http.StatusBadRequest)
		return
	}

	// Determine destination based on prefix
	// assume if token starts with sha256~ it should be forwarded to OpenShift Internal Oauth webhook
	// otherwise assume should be forwarded to external webhook
	// HACK: there doesn't seem to be any better way to differentiate
	var upstreamWebhookTarget *UpstreamWebhookTarget
	if strings.HasPrefix(review.Spec.Token, "sha256~") {
		upstreamWebhookTarget = h.openShiftWebhookTarget
	} else {
		upstreamWebhookTarget = h.externalWebhookTarget
	}

	// Forward using the pre-cached target details
	if err := h.handleForwarding(upstreamWebhookTarget, review, w, request); err != nil {
		slog.Error("forwarding failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

func (h *webhookHandler) handleForwarding(upstreamWebhookTarget *UpstreamWebhookTarget, review TokenReview, w http.ResponseWriter, request *http.Request) error {
	// create connection to upstream webhook client
	upstreamClient := &http.Client{
		Transport: &http.Transport{TLSClientConfig: upstreamWebhookTarget.TLSConfig},
		Timeout:   30 * time.Second,
	}

	// Forward the request and get the response back
	slog.Info("Forwarding request to upstream webhook", "requestor", request.RemoteAddr, "webhook", upstreamWebhookTarget.Server)
	upstreamResp, err := forwardRequest(upstreamClient, upstreamWebhookTarget.Server, review)
	if err != nil {
		return fmt.Errorf("failed to forward the TokenReview: %w", err)
	}

	// Use the new helper to write the response back to the client
	slog.Info("Writing response from upstream webhook back to requestor", "requestor", request.RemoteAddr, "webhook", upstreamWebhookTarget.Server)
	return writeForwardedRequestResponse(w, upstreamResp)
}

func getCurrentContext(cfg KubeConfig) (*NamedContext, error) {
	currentContextName := cfg.CurrentContext
	if currentContextName == "" {
		return nil, fmt.Errorf("current-context is not set in kubeconfig")
	}

	for i := range cfg.Contexts {
		if cfg.Contexts[i].Name == currentContextName {
			return &cfg.Contexts[i], nil
		}
	}

	return nil, fmt.Errorf("context %q not found in contexts list", currentContextName)
}

func getClusterByCurrentContext(cfg KubeConfig) (*NamedCluster, error) {
	// Use the new helper to get the context
	targetContext, err := getCurrentContext(cfg)
	if err != nil {
		return nil, err
	}

	targetClusterName := targetContext.Context.Cluster
	for i := range cfg.Clusters {
		if cfg.Clusters[i].Name == targetClusterName {
			return &cfg.Clusters[i], nil
		}
	}

	return nil, fmt.Errorf("cluster %q (referenced by context %q) not found", targetClusterName, cfg.CurrentContext)
}

func getUserByCurrentContext(cfg KubeConfig) (*NamedUser, error) {
	// Use the new helper to get the context
	targetContext, err := getCurrentContext(cfg)
	if err != nil {
		return nil, err
	}

	targetUserName := targetContext.Context.User
	for i := range cfg.Users {
		if cfg.Users[i].Name == targetUserName {
			return &cfg.Users[i], nil
		}
	}

	return nil, fmt.Errorf("user %q (referenced by context %q) not found", targetUserName, cfg.CurrentContext)
}

func forwardRequest(upstreamClient *http.Client, url string, review TokenReview) (*http.Response, error) {
	upstreamBody, err := json.Marshal(review)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal TokenReview to json: %w", err)
	}

	resp, err := upstreamClient.Post(url, "application/json", bytes.NewBuffer(upstreamBody))
	if err != nil {
		return nil, fmt.Errorf("failed to post TokenReview to upstream webhook (%s): %w", url, err)
	}

	return resp, nil
}

func writeForwardedRequestResponse(w http.ResponseWriter, upstreamResp *http.Response) error {
	// Copy relevant headers from the upstream response
	w.Header().Set("Content-Type", "application/json")

	// Write the upstream status code
	w.WriteHeader(upstreamResp.StatusCode)

	// Stream the body directly to the original ResponseWriter
	if _, err := io.Copy(w, upstreamResp.Body); err != nil {
		return fmt.Errorf("failed to copy response from upstream webhook to client: %w", err)
	}
	defer upstreamResp.Body.Close()

	return nil
}

func createTLSConfig(serverName string, serverCAB64 string, clientCertificateB64 string, clientKeyB64 string) (*tls.Config, error) {
	caData, err := base64.StdEncoding.DecodeString(serverCAB64)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caData)

	tlsConfig := &tls.Config{
		RootCAs:    pool,
		ServerName: serverName,
	}

	if clientCertificateB64 != "" && clientKeyB64 != "" {
		c, _ := base64.StdEncoding.DecodeString(clientCertificateB64)
		k, _ := base64.StdEncoding.DecodeString(clientKeyB64)
		cert, err := tls.X509KeyPair(c, k)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return tlsConfig, nil
}

func loadKubeConfig(path string) (*KubeConfig, error) {
	configData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read kubeConfig (%s): %w", path, err)
	}

	var cfg KubeConfig
	if err := yaml.Unmarshal(configData, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse kubeConfig (%s): %w", path, err)
	}

	if len(cfg.Clusters) != 1 {
		return nil, fmt.Errorf("invalid kubeConfig (%s): expected one cluster defined", path)
	}

	if len(cfg.Users) != 1 {
		return nil, fmt.Errorf("invalid kubeConfig (%s):: expected one user defined", path)
	}

	if len(cfg.Contexts) != 1 {
		return nil, fmt.Errorf("invalid kubeConfig (%s):: expected one context defined", path)
	}

	if cfg.CurrentContext == "" {
		return nil, fmt.Errorf("invalid kubeConfig (%s):: current-context is not set", path)
	}

	return &cfg, nil
}

func main() {
	command := flag.String("command", "", "Command to execute: serve")
	tlsCert := flag.String("tls-cert", "", "Path to TLS certificate")
	tlsKey := flag.String("tls-key", "", "Path to TLS key")
	addr := flag.String("addr", ":8443", "Listen address")

	// New Flags
	openShiftWebhookKubeConfigPath := flag.String("openshift-webhook-kubeconfig", "/etc/webhook/openshift.kubeconfig", "Path to OpenShift kubeconfig")
	externalWebhookKubeConfigPath := flag.String("external-webhook-kubeconfig", "/etc/webhook/external.kubeconfig", "Path to external webhook kubeconfig")

	flag.Parse()

	switch *command {
	case "serve":
		if *tlsCert == "" || *tlsKey == "" {
			slog.Error("serve requires -tls-cert, and -tls-key")
			os.Exit(1)
		}

		if err := serve(*tlsCert, *tlsKey, *addr, *openShiftWebhookKubeConfigPath, *externalWebhookKubeConfigPath); err != nil {
			slog.Error("Server error", "error", err)
			os.Exit(1)
		}
	default:
		slog.Error("command required: use -command serve")
		os.Exit(1)
	}
}
