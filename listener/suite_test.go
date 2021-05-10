package listener

import (
	"github.com/brianvoe/gofakeit/v6"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"go.uber.org/zap"
	"testing"
)

var (
	logger = zap.NewNop()
	fake   = gofakeit.New(0)
)

func TestListener(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Listener Suite")
}
