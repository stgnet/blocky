package resolver

import (
	"github.com/stgnet/blocky/config"
	. "github.com/stgnet/blocky/helpertest"

	"github.com/miekg/dns"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

var _ = Describe("CnameResolver", func() {
	var (
		sut  ChainedResolver
		m    *resolverMock
		err  error
		resp *Response
	)

	BeforeEach(func() {
		sut = NewCnameResolver(config.CnameConfig{
			Groups: map[string]config.Groups{
				"youtube": {
					Domains: []string{"youtube.com", "other.youtube.com"},
					Cname:   "restrict.youtube.com",
				},
			},
			ClientGroupsBlock: map[string][]string{
				"192.168.2.1": {"youtube"},
			},
		})
		m = &resolverMock{}
		m.On("Resolve", mock.Anything).Return(&Response{Res: new(dns.Msg)}, nil)
		sut.Next(m)
	})

	Describe("Resolving a restricted domain", func() {
		When("A domain restriction is defined for a domain", func() {
			It("should respond with the restricted CNAME", func() {
				resp, err = sut.Resolve(newRequestWithClient("other.youtube.com", dns.TypeA, "1.2.1.2", "192.168.2.1"))

				Expect(resp.Res.Rcode).Should(Equal(dns.RcodeSuccess))
				Expect(resp.Res.Answer).Should(BeDNSRecord("other.youtube.com", dns.TypeA, 3600, "restrict.youtube.com"))
			})
		})
		AfterEach(func() {
			// will not delegate to next resolver
			m.AssertNotCalled(GinkgoT(), "Resolve", mock.Anything)
			Expect(err).Should(Succeed())
		})
	})

})
