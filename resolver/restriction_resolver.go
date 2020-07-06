package resolver

import (
	"fmt"
	"sort"
	"strings"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/stgnet/blocky/config"
	"github.com/stgnet/blocky/util"
)

type RestrictionResolver struct {
	NextResolver
	cfg config.CnameConfig
}

// NewRestrictionResolver resturns a new restriction resolver
func NewRestrictionResolver(cfg config.CnameConfig) ChainedResolver {
	return &RestrictionResolver{cfg: cfg}
}

// Configuration returns the string representation of the configuration
func (rr *RestrictionResolver) Configuration() (result []string) {

	for k, val := range rr.cfg.Groups {
		result = append(result, fmt.Sprintf("group %s redirects to %s", k, val.Cname))
		for _, v := range val.Domains {
			result = append(result, fmt.Sprintf("domain %s", v))
		}
	}

	for key, val := range rr.cfg.ClientGroupsBlock {
		result = append(result, fmt.Sprintf("  %s = \"%s\"", key, strings.Join(val, ";")))
	}

	return
}

// Resolve ...
func (rr *RestrictionResolver) Resolve(req *Request) (*Response, error) {
	logger := withPrefix(req.Log, "restriction_resolver")

	for _, question := range req.Req.Question {
		domain := util.ExtractDomain(question)
		groups := rr.groupsToCheckForClient(req)

		for len(domain) > 0 {
			for _, v := range groups {
				if v == domain {
					response := new(dns.Msg)
					response.SetReply(req.Req)

					dnsCnameReq := new(dns.CNAME)
					h := dns.RR_Header{Name: question.Name, Rrtype: question.Qtype, Class: dns.ClassINET, Ttl: customDNSTTL}

					dnsCnameReq.Target = rr.cfg.Groups[v].Cname
					dnsCnameReq.Hdr = h

					response.Answer = append(response.Answer, dnsCnameReq)

					logger.WithFields(logrus.Fields{
						"answer": util.AnswerToString(response.Answer),
						"domain": domain,
					}).Debugf("returning custom dns entry")

					return &Response{Res: response, RType: CUSTOMDNS, Reason: "CUSTOM DNS"}, nil
				}
			}
		}
	}
	return nil, nil
}

func (rr *RestrictionResolver) groupsToCheckForClient(request *Request) (groups []string) {
	// try client names
	for _, cName := range request.ClientNames {
		groupsByName, found := rr.cfg.ClientGroupsBlock[cName]
		if found {
			groups = append(groups, groupsByName...)
		}
	}

	// if len(groups) == 0 {
	// 	if !found {
	// 		// return default
	// 		groups = rr.cfg.ClientGroupsBlock["default"]
	// 	}
	// }

	sort.Strings(groups)

	return
}
