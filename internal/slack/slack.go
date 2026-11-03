package slack

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
)

// Send a single aggregated message, including the channel mention in the body.
func PostMessage(ctx context.Context, client *http.Client, token, channel, message string) error {
	payload, err := json.Marshal(struct {
		Channel     string `json:"channel"`
		Text        string `json:"text"`
		Parse       string `json:"parse"`
		UnfurlLinks bool   `json:"unfurl_links"`
		UnfurlMedia bool   `json:"unfurl_media"`
	}{Channel: channel, Text: "<!channel>\n" + message, Parse: "none"})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://slack.com/api/chat.postMessage", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	// Do not follow redirects with an authenticated API request.
	safeClient := *client
	safeClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := safeClient.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("Slack通知: %w", ctx.Err())
		}
		return errors.New("Slack通知: HTTPリクエスト失敗")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("Slack通知: HTTP %d", res.StatusCode)
	}
	var response struct {
		OK               bool   `json:"ok"`
		Error            string `json:"error"`
		ResponseMetadata struct {
			Warnings []string `json:"warnings"`
		} `json:"response_metadata"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 64*1024)).Decode(&response); err != nil {
		return errors.New("Slack通知: 不正なAPIレスポンス")
	}
	if !response.OK {
		// Only log Slack's error code, never its raw response or authentication data.
		code := response.Error
		if !regexp.MustCompile(`^[a-z_]+$`).MatchString(code) {
			code = "unknown_error"
		}
		return fmt.Errorf("Slack通知失敗: %s", code)
	}
	for _, warning := range response.ResponseMetadata.Warnings {
		if warning == "message_truncated" {
			return errors.New("Slack通知: メッセージが切り詰められました")
		}
	}
	return nil
}
