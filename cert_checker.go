package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"
)

var certDialer = &tls.Dialer{}

// RunCertCheck connects to host via TLS and checks certificate expiry.
func RunCertCheck(cfg *Config, check CheckEntry) CheckResult {
	result := CheckResult{Check: check, OK: true}

	host := check.Host
	if host == "" {
		host = cfg.Domain + ":443"
	}

	warnDays := check.WarnDays
	if warnDays == 0 {
		warnDays = 30
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := certDialer.DialContext(ctx, "tcp", host)
	if err != nil {
		result.OK = false
		result.Error = fmt.Sprintf("TLS connection to %s failed: %v", host, err)
		return result
	}
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		result.OK = false
		result.Error = "connection is not TLS"
		return result
	}

	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		result.OK = false
		result.Error = fmt.Sprintf("no certificates returned from %s", host)
		return result
	}

	leaf := certs[0]
	daysUntilExpiry := int(time.Until(leaf.NotAfter).Hours() / 24)

	if daysUntilExpiry < warnDays {
		result.OK = false
		result.Actual = []string{
			fmt.Sprintf("expires in %d days (%s)", daysUntilExpiry, leaf.NotAfter.Format("2006-01-02")),
		}
	}

	return result
}
