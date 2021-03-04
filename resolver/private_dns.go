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
	toggles := map[string]bool{"adblock": false, "malware": false, "adult": false}
	uniqueGroups := buildGroupsMap(groupsToCheck)
	for k, v := range r.cfg.Global {
		toggles[k] = v
	}

	logger("private_resolver").Debugf("global: %v, toggles: %v, groupsToCheck: %v ***!", r.cfg.Global, toggles, uniqueGroups)
	// Global State	| Device State	| Result for Device
	// -----------------------------------------------
	// OFF (False)	| ON (True)		| OFF |
	// OFF (False)	| OFF (False)	| OFF |
	// ON (True)	| ON (True)		| ON  |
	// ON (True)	| OFF (False)	| OFF |

	for k, v := range toggles {
		v2, _ := uniqueGroups[k]

		if v && v2 {
			toggles[k] = true
			continue
		}
		toggles[k] = false
		continue

	}

	logger("private_resolver").Debugf("final toggles %v", toggles)
	// calculate result
	values := map[string]int{"adblock": 1, "malware": 2, "adult": 4}
	port := 1024
	for k, v := range toggles {
		if v {
			if i, ok := values[k]; ok {
				port += i
			}
		}
	}
	if port > 1031 {
		logger("private_resolver").Error("port returned a value greater than the maximum of 1031. Setting to 1024", port)
		port = 1024
	}

	return port

}
func buildGroupsMap(slice []string) map[string]bool {
	m := map[string]bool{}
	for _, entry := range slice {
		m[entry] = true
	}

	return m
}

func getEdnsData(request *Request, cfg map[string][]string, groups []string) {
	opt := request.Req.IsEdns0()
	if opt != nil {
		data := (opt.Option[0].(*dns.EDNS0_LOCAL)).Data
		macStr := net.HardwareAddr(data).String()
		groupsByName, found := cfg[macStr]
		if found {
			groups = append(groups, groupsByName...)
		}

		logger("groups_to_check").Debugf("macstr: %s, groups: %v", macStr, groups)
	}
}
