package resolver

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/stgnet/blocky/util"
)

func callExternal(msg *dns.Msg, upstreamURL string) (*dns.Msg, time.Duration, error) {
	start := time.Now()

	rawDNSMessage, err := msg.Pack()

	if err != nil {
		return nil, 0, fmt.Errorf("can't pack message: %v", err)
	}

	c := http.DefaultClient
	c.Timeout = defaultTimeout
	httpResponse, err := c.Post(upstreamURL, dnsContentType, bytes.NewReader(rawDNSMessage))

	if err != nil {
		return nil, 0, fmt.Errorf("can't perform https request: %v", err)
	}
	defer httpResponse.Body.Close()

	if httpResponse.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("http return code should be %d, but received %d", http.StatusOK, httpResponse.StatusCode)
	}

	contentType := httpResponse.Header.Get("content-type")
	if contentType != dnsContentType {
		return nil, 0, fmt.Errorf("http return content type should be '%s', but was '%s'",
			dnsContentType, contentType)
	}

	body, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, 0, errors.New("can't read response body")
	}

	response := dns.Msg{}
	err = response.Unpack(body)

	if err != nil {
		return nil, 0, errors.New("can't unpack message")
	}

	return &response, time.Since(start), nil
}

func resolvePrivate(request *Request, port int) (response *Response, err error) {
	logger := withPrefix(request.Log, "private_resolver")
	net := "http"
	host := "10.255.0.1"
	url := fmt.Sprintf("%s://%s:%d", net, host, port)

	var rtt time.Duration
	var resp *dns.Msg
	if resp, rtt, err = callExternal(request.Req, url); err == nil {
		logger.WithFields(logrus.Fields{
			"answer":           util.AnswerToString(resp.Answer),
			"return_code":      dns.RcodeToString[resp.Rcode],
			"upstream":         url,
			"response_time_ms": rtt.Milliseconds(),
		}).Debugf("received response from private dns")

		return &Response{Res: resp, Reason: fmt.Sprintf("RESOLVED (%s)", url)}, err
	}

	return nil, fmt.Errorf("could not resolve using private dns %w", err)
}

func contains(domain string, cache []string) bool {
	idx := sort.SearchStrings(cache, domain)
	if idx < len(cache) {
		return cache[idx] == strings.ToLower(domain)
	}

	return false
}

func (r *BlockingResolver) getPort(groupsToCheck []string) int {
	toggles := []string{}

	for k, v := range r.cfg.Global {
		if v {
			toggles = append(toggles, k)
		}
	}

	for _, v := range groupsToCheck {
		if !contains(v, toggles) {
			toggles = append(toggles, v)
		}
	}

	values := map[string]int{"adblock": 1, "malware": 2, "adult": 4}
	port := 1024
	for _, v := range toggles {
		if int, ok := values[v]; ok {
			port += int
		}
	}
	return port

}
