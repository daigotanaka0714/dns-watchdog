package main

import "fmt"

// DNS response codes (RFC 1035, RFC 5395) that the diagnosis distinguishes.
const (
	rcodeNoError  = 0
	rcodeServFail = 2
	rcodeNXDomain = 3
	rcodeRefused  = 5
)

// Suggestion is a likely cause and a next step for a failed check.
// Cause and Action are label keys; CauseArg, when set, fills the %d in the
// cause label.
type Suggestion struct {
	Cause    string
	CauseArg int
	Action   string
}

// Diagnose derives a suggestion from what the resolver reported for a failed
// DoH record check. It returns false when the result carries nothing to go on,
// in which case the caller keeps the generic action for the check type.
func Diagnose(r CheckResult) (Suggestion, bool) {
	q := r.Query
	if q == nil {
		return Suggestion{}, false
	}

	// The DoH endpoint itself rejected or failed the request.
	if q.HTTPStatus != 0 {
		switch {
		case q.HTTPStatus == 429:
			return Suggestion{Cause: "cause_http_rate_limited", Action: "action_retry"}, true
		case q.HTTPStatus >= 400 && q.HTTPStatus < 500:
			return Suggestion{Cause: "cause_http_client_error", CauseArg: q.HTTPStatus, Action: "action_check_config"}, true
		case q.HTTPStatus >= 500:
			return Suggestion{Cause: "cause_http_server_error", CauseArg: q.HTTPStatus, Action: "action_retry"}, true
		}
		return Suggestion{}, false
	}

	// Other errors (timeouts, connection failures) have no resolver answer.
	if r.Error != "" {
		return Suggestion{}, false
	}

	switch q.RCode {
	case rcodeNXDomain:
		return Suggestion{Cause: "cause_nxdomain", Action: "action_check_name_and_expiry"}, true
	case rcodeServFail:
		return Suggestion{Cause: "cause_servfail", Action: "action_check_dnssec_ns"}, true
	case rcodeRefused:
		return Suggestion{Cause: "cause_refused", Action: "action_check_ns"}, true
	case rcodeNoError:
		if len(r.Actual) == 0 {
			return Suggestion{Cause: "cause_no_records", Action: "action_add_record"}, true
		}
		if q.TTL > 0 {
			return Suggestion{Cause: "cause_ttl_stale", CauseArg: q.TTL, Action: "action_wait_propagation"}, true
		}
	}
	return Suggestion{}, false
}

// formatCause renders the cause label of a suggestion.
func (s Suggestion) formatCause(labels map[string]string) string {
	text := labels[s.Cause]
	if s.CauseArg != 0 {
		return fmt.Sprintf(text, s.CauseArg)
	}
	return text
}
