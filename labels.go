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
	"cause":                         "Likely cause",
	"cause_http_rate_limited":       "The DNS-over-HTTPS resolver is rate limiting requests",
	"cause_http_client_error":       "The DNS-over-HTTPS resolver rejected the query (HTTP %d)",
	"cause_http_server_error":       "The DNS-over-HTTPS resolver is failing (HTTP %d)",
	"cause_nxdomain":                "The name does not exist (NXDOMAIN): a wrong name, a deleted record, or an expired domain",
	"cause_servfail":                "The resolver could not get a valid answer (SERVFAIL): often a DNSSEC validation failure or an unresponsive nameserver",
	"cause_refused":                 "A nameserver refused the query (REFUSED): the zone may not be served there",
	"cause_no_records":              "The name exists but has no record of this type",
	"cause_ttl_stale":               "If this record was changed recently, resolvers can keep the old value for up to %d seconds (TTL)",
	"action_check_config":           "Check the name and type in the config",
	"action_check_name_and_expiry":  "Check the record name and the domain registration",
	"action_check_dnssec_ns":        "Check DNSSEC (DS records) and nameserver health",
	"action_add_record":             "Add the missing record",
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
	"cause":                         "考えられる原因",
	"cause_http_rate_limited":       "DNS-over-HTTPS リゾルバがリクエストを制限しています",
	"cause_http_client_error":       "DNS-over-HTTPS リゾルバがクエリを拒否しました（HTTP %d）",
	"cause_http_server_error":       "DNS-over-HTTPS リゾルバに障害が出ています（HTTP %d）",
	"cause_nxdomain":                "名前が存在しません（NXDOMAIN）。名前の誤り、レコードの削除、ドメインの失効のいずれかが考えられます",
	"cause_servfail":                "リゾルバが有効な応答を得られませんでした（SERVFAIL）。DNSSEC の検証失敗やネームサーバーの無応答が多い原因です",
	"cause_refused":                 "ネームサーバーがクエリを拒否しました（REFUSED）。そのサーバーにゾーンが無い可能性があります",
	"cause_no_records":              "名前は存在しますが、この種類のレコードがありません",
	"cause_ttl_stale":               "レコードを最近変更した場合、リゾルバは最大 %d 秒（TTL）古い値を保持することがあります",
	"action_check_config":           "設定ファイルの名前と種類を確認",
	"action_check_name_and_expiry":  "レコード名とドメイン登録を確認",
	"action_check_dnssec_ns":        "DNSSEC（DS レコード）とネームサーバーの状態を確認",
	"action_add_record":             "不足しているレコードを追加",
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
