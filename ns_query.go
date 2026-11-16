package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

var nsQueryTimeout = 5 * time.Second

// ednsUDPSize is the UDP payload size advertised in queries (DNS Flag Day 2020).
const ednsUDPSize = 1232

// nsQueryError describes a failed query to one nameserver. Server is the
// address the query was actually sent to.
type nsQueryError struct {
	Server        string
	QType         dnsmessage.Type
	RCode         dnsmessage.RCode
	Authoritative bool
	NoData        bool
	Err           error
}

func (e *nsQueryError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Server, e.Err)
	}
	aa := "authoritative"
	if !e.Authoritative {
		aa = "non-authoritative"
	}
	if e.NoData {
		return fmt.Sprintf("%s answered NOERROR with no %s records (%s)", e.Server, typeName(e.QType), aa)
	}
	return fmt.Sprintf("%s answered %s (%s)", e.Server, rcodeName(e.RCode), aa)
}

func isNoData(err error) bool {
	var qe *nsQueryError
	return errors.As(err, &qe) && qe.NoData
}

func rcodeName(rc dnsmessage.RCode) string {
	switch rc {
	case rcodeNoError:
		return "NOERROR"
	case 1:
		return "FORMERR"
	case rcodeServFail:
		return "SERVFAIL"
	case rcodeNXDomain:
		return "NXDOMAIN"
	case 4:
		return "NOTIMP"
	case rcodeRefused:
		return "REFUSED"
	}
	return fmt.Sprintf("RCODE %d", rc)
}

func typeName(t dnsmessage.Type) string {
	return strings.TrimPrefix(t.String(), "Type")
}

// queryNameserver sends the query straight to ns (host or host:port) without
// recursion or search domains, and returns the records in the same form the
// consistency check compares.
func queryNameserver(domain, ns, qtype string) ([]string, error) {
	server, err := nameserverAddr(ns)
	if err != nil {
		return nil, err
	}
	switch qtype {
	case "A":
		// Matches net.LookupHost: IPv4 and IPv6 addresses together.
		v4, errV4 := exchangeRecords(server, domain, dnsmessage.TypeA)
		v6, errV6 := exchangeRecords(server, domain, dnsmessage.TypeAAAA)
		if addrs := append(v4, v6...); len(addrs) > 0 {
			return addrs, nil
		}
		// Report a failure over "no records" when one family has it.
		if errV6 != nil && !isNoData(errV6) && isNoData(errV4) {
			return nil, errV6
		}
		return nil, errV4
	case "MX":
		return exchangeRecords(server, domain, dnsmessage.TypeMX)
	case "TXT":
		return exchangeRecords(server, domain, dnsmessage.TypeTXT)
	case "NS":
		return exchangeRecords(server, domain, dnsmessage.TypeNS)
	default:
		return nil, fmt.Errorf("unsupported query type for NS consistency: %s", qtype)
	}
}

// nameserverAddr resolves the nameserver host and returns ip:port, preferring
// IPv4.
func nameserverAddr(ns string) (string, error) {
	host, port, err := net.SplitHostPort(ns)
	if err != nil {
		host, port = ns, "53"
	}
	ctx, cancel := context.WithTimeout(context.Background(), nsQueryTimeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return "", fmt.Errorf("resolve nameserver %s: %w", host, err)
	}
	ip := addrs[0]
	for _, a := range addrs {
		if parsed := net.ParseIP(a); parsed != nil && parsed.To4() != nil {
			ip = a
			break
		}
	}
	return net.JoinHostPort(ip, port), nil
}

func exchangeRecords(server, domain string, qtype dnsmessage.Type) ([]string, error) {
	fail := func(err error) error { return &nsQueryError{Server: server, QType: qtype, Err: err} }

	name, err := dnsmessage.NewName(strings.TrimSuffix(domain, ".") + ".")
	if err != nil {
		return nil, fail(err)
	}
	id := uint16(rand.Uint32())
	query, err := buildQuery(id, name, qtype)
	if err != nil {
		return nil, fail(err)
	}

	resp, err := roundTrip("udp", server, query, id)
	if err == nil {
		var h dnsmessage.Header
		var p dnsmessage.Parser
		if h, err = p.Start(resp); err == nil && h.Truncated {
			resp, err = roundTrip("tcp", server, query, id)
		}
	}
	if err != nil {
		return nil, fail(err)
	}
	return parseAnswer(resp, server, qtype)
}

func buildQuery(id uint16, name dnsmessage.Name, qtype dnsmessage.Type) ([]byte, error) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{Name: name, Type: qtype, Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	if err := b.StartAdditionals(); err != nil {
		return nil, err
	}
	var opt dnsmessage.ResourceHeader
	if err := opt.SetEDNS0(ednsUDPSize, dnsmessage.RCodeSuccess, false); err != nil {
		return nil, err
	}
	if err := b.OPTResource(opt, dnsmessage.OPTResource{}); err != nil {
		return nil, err
	}
	return b.Finish()
}

// roundTrip sends query over UDP or TCP and returns the response with the
// matching ID.
func roundTrip(network, server string, query []byte, id uint16) ([]byte, error) {
	conn, err := net.DialTimeout(network, server, nsQueryTimeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(nsQueryTimeout)); err != nil {
		return nil, err
	}

	if network == "tcp" {
		framed := binary.BigEndian.AppendUint16(nil, uint16(len(query)))
		if _, err := conn.Write(append(framed, query...)); err != nil {
			return nil, err
		}
		var length [2]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			return nil, err
		}
		resp := make([]byte, binary.BigEndian.Uint16(length[:]))
		if _, err := io.ReadFull(conn, resp); err != nil {
			return nil, err
		}
		if len(resp) < 2 || binary.BigEndian.Uint16(resp) != id {
			return nil, errors.New("response ID does not match the query")
		}
		return resp, nil
	}

	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		// Ignore stray datagrams until the deadline.
		if n >= 2 && binary.BigEndian.Uint16(buf) == id {
			return buf[:n], nil
		}
	}
}

func parseAnswer(resp []byte, server string, qtype dnsmessage.Type) ([]string, error) {
	var p dnsmessage.Parser
	h, err := p.Start(resp)
	if err != nil {
		return nil, &nsQueryError{Server: server, QType: qtype, Err: fmt.Errorf("parse response: %w", err)}
	}
	if h.RCode != dnsmessage.RCodeSuccess {
		return nil, &nsQueryError{Server: server, QType: qtype, RCode: h.RCode, Authoritative: h.Authoritative}
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, &nsQueryError{Server: server, QType: qtype, Err: fmt.Errorf("parse response: %w", err)}
	}

	var records []string
	for {
		rh, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, &nsQueryError{Server: server, QType: qtype, Err: fmt.Errorf("parse response: %w", err)}
		}
		if rh.Type != qtype {
			if err := p.SkipAnswer(); err != nil {
				return nil, &nsQueryError{Server: server, QType: qtype, Err: fmt.Errorf("parse response: %w", err)}
			}
			continue
		}
		rec, err := answerString(&p, qtype)
		if err != nil {
			return nil, &nsQueryError{Server: server, QType: qtype, Err: fmt.Errorf("parse response: %w", err)}
		}
		records = append(records, rec)
	}

	if len(records) == 0 {
		return nil, &nsQueryError{Server: server, QType: qtype, Authoritative: h.Authoritative, NoData: true}
	}
	return records, nil
}

func answerString(p *dnsmessage.Parser, qtype dnsmessage.Type) (string, error) {
	switch qtype {
	case dnsmessage.TypeA:
		r, err := p.AResource()
		return net.IP(r.A[:]).String(), err
	case dnsmessage.TypeAAAA:
		r, err := p.AAAAResource()
		return net.IP(r.AAAA[:]).String(), err
	case dnsmessage.TypeMX:
		r, err := p.MXResource()
		return fmt.Sprintf("%d %s", r.Pref, r.MX.String()), err
	case dnsmessage.TypeTXT:
		// Matches net.LookupTXT: the strings of one record are concatenated.
		r, err := p.TXTResource()
		return strings.Join(r.TXT, ""), err
	case dnsmessage.TypeNS:
		r, err := p.NSResource()
		return r.NS.String(), err
	}
	return "", fmt.Errorf("unsupported answer type %s", typeName(qtype))
}
