package util

import "github.com/linode/linodego"

func NewLinodeClient(token, ua string, url string) *linodego.Client {
	linodeClient := linodego.NewClient(nil)
	linodeClient.SetUserAgent(ua)
	linodeClient.SetToken(token)

	if url != "" {
		linodeClient.SetBaseURL(url)
	}

	return &linodeClient
}
