package main

var labelsEN = map[string]string{
	"title":                         "DNS Alert: %s",
	"error":                         "ERROR",
	"warning":                       "WARNING",
	"record":                        "Record",
	"domain":                        "Domain",
	"action":                        "Action",
	"footer":                        "dns-watchdog",
	"summary_dns_mismatch":          "%s record mismatch",
	"summary_dns_contains_mismatch": "%s record missing expected content",
	"summary_cert_expiry":           "Certificate expires in %s",
	"summary_whois_expiry":          "Domain expires in %s",
	"summary_blocklist":             "IP listed on blocklist",
	"summary_ns_inconsistency":      "NS records inconsistent",
	"summary_propagation":           "DNS propagation mismatch",
	"action_retry":                  "Retry in next cycle",
	"action_verify_dns":             "Verify DNS configuration",
	"action_renew_cert":             "Renew SSL certificate",
	"action_renew_domain":           "Renew domain registration",
	"action_request_delist":         "Request delisting",
	"action_check_ns":               "Check NS configuration",
	"action_wait_propagation":       "Wait or verify records",
}

var labelsJA = map[string]string{
	"title":                         "DNS異常検知: %s",
	"error":                         "エラー",
	"warning":                       "警告",
	"record":                        "レコード",
	"domain":                        "ドメイン",
	"action":                        "対応",
	"footer":                        "dns-watchdog",
	"summary_dns_mismatch":          "%sレコード不一致",
	"summary_dns_contains_mismatch": "%sレコードに期待する内容が不在",
	"summary_cert_expiry":           "証明書期限: %s",
	"summary_whois_expiry":          "ドメイン期限: %s",
	"summary_blocklist":             "ブロックリスト検知",
	"summary_ns_inconsistency":      "ネームサーバー不整合",
	"summary_propagation":           "DNS伝播不一致",
	"action_retry":                  "次のサイクルで再試行",
	"action_verify_dns":             "DNS設定を確認",
	"action_renew_cert":             "SSL証明書を更新",
	"action_renew_domain":           "ドメイン登録を更新",
	"action_request_delist":         "デリスト申請",
	"action_check_ns":               "NS設定を確認",
	"action_wait_propagation":       "伝播待ちまたはレコード確認",
}

var builtinLabels = map[string]map[string]string{
	"en": labelsEN,
	"ja": labelsJA,
}

// ResolveLabels returns a merged label map for the given language.
// If language is unsupported, falls back to "en".
// customLabels override built-in values; unknown keys are ignored.
func ResolveLabels(language string, customLabels map[string]string) map[string]string {
	base, ok := builtinLabels[language]
	if !ok {
		base = labelsEN
	}

	merged := make(map[string]string, len(base))
	for k, v := range base {
		merged[k] = v
	}

	for k, v := range customLabels {
		if _, exists := merged[k]; exists {
			merged[k] = v
		}
	}

	return merged
}
