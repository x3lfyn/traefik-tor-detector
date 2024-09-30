package traefik_tor_detector

import (
	"context"
	"errors"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
)

type Config struct {
}

func CreateConfig() *Config {
	return &Config{}
}

type Demo struct {
	next   http.Handler
	name   string
	torIps []string
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	res, err := http.Get("https://check.torproject.org/torbulkexitlist")
	if err != nil {
		return nil, err
	}
	if res.StatusCode != 200 {
		return nil, errors.New("failed to get Tor exit nodes list. server returned non 200 response")
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var ips []string
	for _, line := range strings.Split(string(body), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			ips = append(ips, trimmed)
		}
	}

	return &Demo{
		next:   next,
		name:   name,
		torIps: ips,
	}, nil
}

func (a *Demo) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	clientIp := req.Header.Get("X-Real-Ip")

	isTor := slices.Contains(a.torIps, clientIp)

	req.Header.Add("X-Tor", strconv.FormatBool(isTor))

	a.next.ServeHTTP(rw, req)
}
