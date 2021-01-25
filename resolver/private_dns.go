package resolver

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/stgnet/blocky/util"
)

func callExternal(msg *dns.Msg, upstreamURL string) (*dns.Msg, time.Duration, error) {

	dnsClient := &dnsUpstreamClient{
		client: &dns.Client{
			Net:     "udp",
			Timeout: defaultTimeout,
		},
	}
	return dnsClient.callExternal(msg, upstreamURL)

}

func resolvePrivate(request *Request, port int) (response *Response, err error) {
	logger := withPrefix(request.Log, "private_resolver")
	host := "10.255.0.1"
	url := net.JoinHostPort(host, strconv.Itoa(port))

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
		if i, ok := values[v]; ok {
			port += i
		}
	}
	return port

}
