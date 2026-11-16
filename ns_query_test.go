package main

import (
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

type fakeAnswer struct {
	rcode     dnsmessage.RCode
	notAuth   bool
	truncated bool
	records   []dnsmessage.Resource
}

// startFakeNS serves answers from handle over UDP and TCP on one port of
// 127.0.0.1 and returns that address.
func startFakeNS(t *testing.T, handle func(q dnsmessage.Question, tcp bool) fakeAnswer) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", ln.Addr().String())
	if err != nil {
		_ = ln.Close()
		t.Skipf("cannot bind UDP on %s: %v", ln.Addr(), err)
	}
	t.Cleanup(func() { _ = ln.Close(); _ = pc.Close() })

	respond := func(req []byte, tcp bool) []byte {
		var p dnsmessage.Parser
		h, err := p.Start(req)
		if err != nil {
			return nil
		}
		q, err := p.Question()
		if err != nil {
			return nil
		}
		a := handle(q, tcp)
		msg := dnsmessage.Message{
			Header: dnsmessage.Header{
				ID: h.ID, Response: true, RCode: a.rcode,
				Authoritative: !a.notAuth, Truncated: a.truncated,
			},
			Questions: []dnsmessage.Question{q},
			Answers:   a.records,
		}
		b, err := msg.Pack()
		if err != nil {
			t.Errorf("pack: %v", err)
			return nil
		}
		return b
	}

	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if resp := respond(buf[:n], false); resp != nil {
				_, _ = pc.WriteTo(resp, addr)
			}
		}
	}()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				var length [2]byte
				if _, err := io.ReadFull(conn, length[:]); err != nil {
					return
				}
				req := make([]byte, binary.BigEndian.Uint16(length[:]))
				if _, err := io.ReadFull(conn, req); err != nil {
					return
				}
				resp := respond(req, true)
				_, _ = conn.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(resp))), resp...))
			}()
		}
	}()
	return ln.Addr().String()
}

func rr(t *testing.T, name string, body dnsmessage.ResourceBody) dnsmessage.Resource {
	t.Helper()
	n := dnsmessage.MustNewName(name)
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: n, Class: dnsmessage.ClassINET, TTL: 300},
		Body:   body,
	}
}

func TestQueryNameserver_Records(t *testing.T) {
	addr := startFakeNS(t, func(q dnsmessage.Question, _ bool) fakeAnswer {
		name := q.Name.String()
		switch q.Type {
		case dnsmessage.TypeA:
			return fakeAnswer{records: []dnsmessage.Resource{rr(t, name, &dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}})}}
		case dnsmessage.TypeMX:
			return fakeAnswer{records: []dnsmessage.Resource{rr(t, name, &dnsmessage.MXResource{Pref: 10, MX: dnsmessage.MustNewName("mail.example.com.")})}}
		case dnsmessage.TypeTXT:
			return fakeAnswer{records: []dnsmessage.Resource{rr(t, name, &dnsmessage.TXTResource{TXT: []string{"v=spf1 ", "-all"}})}}
		case dnsmessage.TypeNS:
			return fakeAnswer{records: []dnsmessage.Resource{rr(t, name, &dnsmessage.NSResource{NS: dnsmessage.MustNewName("ns1.example.com.")})}}
		}
		return fakeAnswer{}
	})

	tests := map[string]string{
		"A":   "192.0.2.1",
		"MX":  "10 mail.example.com.",
		"TXT": "v=spf1 -all",
		"NS":  "ns1.example.com.",
	}
	for qtype, want := range tests {
		got, err := queryNameserver("example.com", addr, qtype)
		if err != nil {
			t.Errorf("%s: unexpected error: %v", qtype, err)
			continue
		}
		if len(got) != 1 || got[0] != want {
			t.Errorf("%s: got %v, want [%s]", qtype, got, want)
		}
	}
}

func TestQueryNameserver_RCodeInError(t *testing.T) {
	addr := startFakeNS(t, func(dnsmessage.Question, bool) fakeAnswer {
		return fakeAnswer{rcode: dnsmessage.RCodeNameError}
	})

	_, err := queryNameserver("example.com", addr, "MX")
	if err == nil {
		t.Fatal("expected an error for NXDOMAIN")
	}
	want := addr + " answered NXDOMAIN (authoritative)"
	if err.Error() != want {
		t.Errorf("got %q, want %q", err.Error(), want)
	}
}

func TestQueryNameserver_NoData(t *testing.T) {
	addr := startFakeNS(t, func(dnsmessage.Question, bool) fakeAnswer {
		return fakeAnswer{notAuth: true}
	})

	_, err := queryNameserver("example.com", addr, "TXT")
	if err == nil {
		t.Fatal("expected an error for an empty answer")
	}
	want := addr + " answered NOERROR with no TXT records (non-authoritative)"
	if err.Error() != want {
		t.Errorf("got %q, want %q", err.Error(), want)
	}
}

func TestQueryNameserver_AFailureOverAAAANoData(t *testing.T) {
	addr := startFakeNS(t, func(q dnsmessage.Question, _ bool) fakeAnswer {
		if q.Type == dnsmessage.TypeA {
			return fakeAnswer{rcode: dnsmessage.RCodeServerFailure}
		}
		return fakeAnswer{}
	})

	_, err := queryNameserver("example.com", addr, "A")
	if err == nil || !strings.Contains(err.Error(), "answered SERVFAIL") {
		t.Errorf("expected the SERVFAIL from the A query, got %v", err)
	}
}

func TestQueryNameserver_TruncatedRetriesOverTCP(t *testing.T) {
	addr := startFakeNS(t, func(q dnsmessage.Question, tcp bool) fakeAnswer {
		if !tcp {
			return fakeAnswer{truncated: true}
		}
		return fakeAnswer{records: []dnsmessage.Resource{rr(t, q.Name.String(), &dnsmessage.NSResource{NS: dnsmessage.MustNewName("ns1.example.com.")})}}
	})

	got, err := queryNameserver("example.com", addr, "NS")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0] != "ns1.example.com." {
		t.Errorf("got %v, want [ns1.example.com.]", got)
	}
}

func TestQueryNameserver_ResolveFailureNamesHost(t *testing.T) {
	_, err := queryNameserver("example.com", "ns.invalid.", "A")
	if err == nil || !strings.Contains(err.Error(), "resolve nameserver ns.invalid.") {
		t.Errorf("expected a resolve error naming the nameserver, got %v", err)
	}
}
