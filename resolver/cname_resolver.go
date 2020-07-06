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

type CnameResolver struct {
	NextResolver
	cfg config.CnameConfig
}

// NewCnameResolver resturns a new restriction resolver
func NewCnameResolver(cfg config.CnameConfig) ChainedResolver {
	return &CnameResolver{cfg: cfg}
}

// Configuration returns the string representation of the configuration
func (rr *CnameResolver) Configuration() (result []string) {

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

// Resolve requested domain and looks if it's part of any restriction
func (rr *CnameResolver) Resolve(req *Request) (*Response, error) {
	logger := withPrefix(req.Log, "cname_resolver")

	for _, question := range req.Req.Question {
		domain := util.ExtractDomain(question)
		groups := rr.groupsToCheckForClient(req)
		if len(groups) <= 0 {
			continue
		}

		for len(domain) > 0 {
			for _, g := range groups {
				for _, d := range rr.cfg.Groups[g].Domains {
					if d == domain {
						response := new(dns.Msg)
						response.SetReply(req.Req)

						dnsCnameReq := new(dns.CNAME)
						h := dns.RR_Header{Name: question.Name, Rrtype: question.Qtype, Class: dns.ClassINET, Ttl: customDNSTTL}

						dnsCnameReq.Target = rr.cfg.Groups[g].Cname
						dnsCnameReq.Hdr = h

						response.Answer = append(response.Answer, dnsCnameReq)

						logger.WithFields(logrus.Fields{
							"answer": util.AnswerToString(response.Answer),
							"domain": domain,
						}).Debugf("returning restricted dns entry")

						return &Response{Res: response, RType: CUSTOMDNS, Reason: "RESTRICTED DNS"}, nil
					}
				}
			}
		}
	}
	return rr.next.Resolve(req)
}

func (rr *CnameResolver) groupsToCheckForClient(request *Request) (groups []string) {
	// try client names
	for _, cName := range request.ClientNames {
		groupsByName, found := rr.cfg.ClientGroupsBlock[cName]
		if found {
			groups = append(groups, groupsByName...)
		}
	}

	if len(groups) == 0 {
		groups = rr.cfg.ClientGroupsBlock["default"]
	}

	sort.Strings(groups)

	return
}
