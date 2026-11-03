package main

import (
	"context"
	"github.com/catatsuy/tls-cert-watch/internal/slack"
	"net/http"
)

func postSlackMessage(ctx context.Context, client *http.Client, token, channel, message string) error {
	return slack.PostMessage(ctx, client, token, channel, message)
}
