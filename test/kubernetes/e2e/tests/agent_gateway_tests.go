package tests

import (
	"github.com/kgateway-dev/kgateway/v2/test/kubernetes/e2e"
	"github.com/kgateway-dev/kgateway/v2/test/kubernetes/e2e/features/agentgateway"
	"github.com/kgateway-dev/kgateway/v2/test/kubernetes/e2e/features/agentgateway/extauth"
	"github.com/kgateway-dev/kgateway/v2/test/kubernetes/e2e/features/agentgateway/local_rate_limit"
)

func AgentGatewaySuiteRunner() e2e.SuiteRunner {
	agentGatewaySuiteRunner := e2e.NewSuiteRunner(false)
	agentGatewaySuiteRunner.Register("BasicRouting", agentgateway.NewTestingSuite)
	agentGatewaySuiteRunner.Register("Extauth", extauth.NewTestingSuite)
	agentGatewaySuiteRunner.Register("LocalRateLimit", local_rate_limit.NewTestingSuite)

	return agentGatewaySuiteRunner
}
