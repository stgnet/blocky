package resolver_test

import (
	"github.com/stgnet/blocky/log"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestResolver(t *testing.T) {
	log.NewLogger("Warn", "text")
	RegisterFailHandler(Fail)
	RunSpecs(t, "Resolver Suite")
}
