package main

import (
	"fmt"
	"strings"
	"time"
)

func escapeSlack(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func readableRemaining(d time.Duration) string {
	elapsed := d <= 0
	if elapsed {
		d = d.Abs()
	}
	seconds := int64(d / time.Second)
	value := "1秒未満"
	if seconds > 0 {
		value = fmt.Sprintf("%d時間%d分%d秒", seconds/3600, seconds/60%60, seconds%60)
	}
	if elapsed {
		return "期限切れ（" + value + "経過）"
	}
	return value
}

func formatAlert(failures []Result, total int) string {
	var message strings.Builder
	fmt.Fprintf(&message, "*TLS証明書の監視で問題を検出しました*\n検査 %d件中 %d件に問題があります。\n証明書の自動更新・配信設定を確認してください。", total, len(failures))
	for i, r := range failures {
		icon := ":rotating_light:"
		if r.Status == "警告" {
			icon = ":warning:"
		}
		expiry, remaining := "不明（証明書を取得できませんでした）", "不明"
		if r.Certificate != nil {
			expiry = r.Certificate.NotAfter.UTC().Format("2006-01-02 15:04:05 UTC")
			remaining = readableRemaining(r.Remaining)
		}
		var entry strings.Builder
		fmt.Fprintf(&entry, "\n\n%s *%s — %s:%d / %s*\n有効期限: %s\n残り時間: %s\n問題:", icon, escapeSlack(r.Status), escapeSlack(r.Host), r.Port, escapeSlack(r.KeyType), expiry, remaining)
		for _, problem := range r.Problems {
			// Raw OpenSSL diagnostics remain in the execution log. Keep notifications readable.
			if strings.HasPrefix(problem, "openssl_stderr=") {
				continue
			}
			runes := []rune(problem)
			if len(runes) > 240 {
				problem = string(runes[:240]) + "…（詳細は実行ログ）"
			}
			fmt.Fprintf(&entry, "\n• %s", escapeSlack(problem))
		}
		// Leave room for the mention and omission notice under Slack's 40,000-character limit.
		if len([]rune(message.String()))+len([]rune(entry.String())) > 35000 {
			fmt.Fprintf(&message, "\n\nほか%d件に問題があります。全件の詳細は実行ログを確認してください。", len(failures)-i)
			break
		}
		message.WriteString(entry.String())
	}
	return message.String()
}
