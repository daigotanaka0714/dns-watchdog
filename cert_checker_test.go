package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newTLSServer(t testing.TB, notAfter time.Time) *httptest.Server {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     notAfter,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}
	server := httptest.NewUnstartedServer(nil)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	server.StartTLS()
	return server
}

func TestRunCertCheck_Valid(t *testing.T) {
	server := newTLSServer(t, time.Now().Add(90 * 24 * time.Hour))
	defer server.Close()

	addr := strings.TrimPrefix(server.URL, "https://")

	origDialer := certDialer
	defer func() { certDialer = origDialer }()
	certDialer = &tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true}}

	cfg := &Config{Domain: "example.com"}
	check := CheckEntry{Type: "CERT_EXPIRY", Name: "@", Host: addr, WarnDays: 30}
	result := RunCertCheck(cfg, check)
	if !result.OK {
		t.Errorf("expected OK=true, got false. Error: %s", result.Error)
	}
}

func TestRunCertCheck_ExpiringSoon(t *testing.T) {
	server := newTLSServer(t, time.Now().Add(10 * 24 * time.Hour))
	defer server.Close()

	addr := strings.TrimPrefix(server.URL, "https://")

	origDialer := certDialer
	defer func() { certDialer = origDialer }()
	certDialer = &tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true}}

	cfg := &Config{Domain: "example.com"}
	check := CheckEntry{Type: "CERT_EXPIRY", Name: "@", Host: addr, WarnDays: 30}
	result := RunCertCheck(cfg, check)
	if result.OK {
		t.Error("expected OK=false for expiring cert")
	}
}

func TestRunCertCheck_AlreadyExpired(t *testing.T) {
	server := newTLSServer(t, time.Now().Add(-5 * 24 * time.Hour))
	defer server.Close()

	addr := strings.TrimPrefix(server.URL, "https://")

	origDialer := certDialer
	defer func() { certDialer = origDialer }()
	certDialer = &tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true}}

	cfg := &Config{Domain: "example.com"}
	check := CheckEntry{Type: "CERT_EXPIRY", Name: "@", Host: addr, WarnDays: 30}
	result := RunCertCheck(cfg, check)
	if result.OK {
		t.Error("expected OK=false for expired cert")
	}
	if len(result.Actual) == 0 || !strings.Contains(result.Actual[0], "期限切れ") {
		t.Errorf("expected 期限切れ message, got: %v", result.Actual)
	}
}
