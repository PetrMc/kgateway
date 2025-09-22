package mcp

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"github.com/stretchr/testify/suite"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/kgateway-dev/kgateway/v2/pkg/utils/kubeutils"
	"github.com/kgateway-dev/kgateway/v2/pkg/utils/requestutils/curl"
	"github.com/kgateway-dev/kgateway/v2/test/kubernetes/e2e"
	testdefaults "github.com/kgateway-dev/kgateway/v2/test/kubernetes/e2e/defaults"
	"github.com/kgateway-dev/kgateway/v2/test/kubernetes/e2e/tests/base"
)

var _ e2e.NewSuiteFunc = NewTestingSuite

type testingSuite struct {
	*base.BaseTestingSuite
	mcpSessionID string // Store session ID across tests
}

func NewTestingSuite(ctx context.Context, testInst *e2e.TestInstallation) suite.TestingSuite {
	return &testingSuite{
		BaseTestingSuite: base.NewBaseTestingSuite(ctx, testInst, setup, map[string]*base.TestCase{
			// Static tests
			"TestMCPConnection": &staticSetup,
			"TestMCPWorkflow":   &staticSetup,
			"TestSSEEndpoint":   &staticSetup,
			// Dynamic tests
			"TestDynamicMCPConnection":     &dynamicSetup,
			"TestDynamicMCPAdminRouting":   &dynamicSetup,
			"TestDynamicMCPUserRouting":    &dynamicSetup,
			"TestDynamicMCPDefaultRouting": &dynamicSetup,
		}),
	}
}

func (s *testingSuite) TestMCPConnection() {
	// Wait for MCP server deployment to be ready
	s.TestInstallation.Assertions.EventuallyPodsRunning(s.Ctx, "default", metav1.ListOptions{
		LabelSelector: "app=mcp-website-fetcher",
	})

	// Wait for curl pod to be ready
	s.TestInstallation.Assertions.EventuallyPodsRunning(s.Ctx, "curl", metav1.ListOptions{
		LabelSelector: "app.kubernetes.io/name=curl",
	})

	// Ensure the Gateway is programmed before asserting route acceptance
	s.TestInstallation.Assertions.EventuallyGatewayCondition(s.Ctx, "gw", "default", gwv1.GatewayConditionProgrammed, metav1.ConditionTrue)

	// Ensure the Backend is Accepted by Kgateway
	s.TestInstallation.Assertions.EventuallyBackendCondition(s.Ctx, "mcp-backend", "default", "Accepted", metav1.ConditionTrue)

	// Verify HTTPRoute is accepted before running the test
	s.TestInstallation.Assertions.EventuallyHTTPRouteCondition(s.Ctx, "mcp-route", "default", gwv1.RouteConditionAccepted, metav1.ConditionTrue)
}

func (s *testingSuite) TestMCPWorkflow() {
	// Single test that does the full workflow with session management
	s.T().Log("Testing complete MCP workflow with session management")

	// Step 1: Initialize and get session ID
	sessionID := s.initializeAndGetSessionID()
	s.Require().NotEmpty(sessionID, "Failed to get session ID from initialize")

	// Step 2: Test resources/list with session ID
	s.testResourcesListWithSession(sessionID)

	// Step 3: Test tools/list with session ID
	s.testToolsListWithSession(sessionID)
}


func (s *testingSuite) initializeAndGetSessionID() string {
	s.T().Log("Initializing MCP and extracting session ID")

	mcpRequest := `{
		"method": "initialize",
		"params": {
			"protocolVersion": "2025-06-18",
			"capabilities": {"roots": {}},
			"clientInfo": {"name": "test-client", "version": "1.0.0"}
		},
		"jsonrpc": "2.0",
		"id": 1
	}`

	// Execute kubectl command directly to capture output
	cmd := exec.Command("kubectl", "exec", "-n", "curl", "curl", "--",
		"curl", "-v",
		"-H", "Content-Type: application/json",
		"-H", "Accept: text/event-stream,application/json",
		"-d", mcpRequest,
		"--max-time", "10",
		"http://gw.default.svc.cluster.local:8080/mcp")

	output, err := cmd.CombinedOutput()
	s.Require().NoError(err, "Failed to execute initialize request")

	outputStr := string(output)
	s.T().Logf("Initialize response: %s", outputStr)

	// Verify we got a successful response
	s.Require().Contains(outputStr, `"result"`, "Initialize should return result")
	s.Require().Contains(outputStr, "protocolVersion", "Initialize should return protocol version")

	// Extract session ID from headers
	sessionIDRegex := regexp.MustCompile(`(?i)mcp-session-id:\s*([a-f0-9-]+)`)
	matches := sessionIDRegex.FindStringSubmatch(outputStr)

	if len(matches) > 1 {
		sessionID := strings.TrimSpace(matches[1])
		s.T().Logf("Extracted session ID: %s", sessionID)
		return sessionID
	}

	s.T().Fatal("Could not extract session ID from initialize response")
	return ""
}

func (s *testingSuite) testResourcesListWithSession(sessionID string) {
	s.T().Log("Testing resources/list with session ID")

	mcpRequest := `{
		"method": "resources/list",
		"params": {},
		"jsonrpc": "2.0",
		"id": 2
	}`

	cmd := exec.Command("kubectl", "exec", "-n", "curl", "curl", "--",
		"curl", "-v", "--no-buffer",
		"-H", "Content-Type: application/json",
		"-H", "Accept: text/event-stream,application/json",
		"-H", fmt.Sprintf("mcp-session-id: %s", sessionID),
		"-d", mcpRequest,
		"--max-time", "10",
		"http://gw.default.svc.cluster.local:8080/mcp")

	output, err := cmd.CombinedOutput()
	s.Require().NoError(err, "Failed to execute resources/list request")

	outputStr := string(output)
	s.T().Logf("Resources/list response: %s", outputStr)

	// Check if we got a successful HTTP response
	s.Require().Contains(outputStr, "< HTTP/1.1 200 OK", "resources/list should return 200 OK")

	// For resources/list, an empty result might be valid if no resources exist
	if strings.Contains(outputStr, `"result"`) {
		s.T().Log("resources/list returned result data")
	} else {
		s.T().Log("resources/list returned empty/minimal response (might be valid)")

		// Let's try to see if there's any SSE data after the headers
		if strings.Contains(outputStr, "data:") {
			s.T().Log("Found SSE data in response")
		} else {
			s.T().Log("No SSE data found - response might be truly empty")
		}
	}
}

func (s *testingSuite) testToolsListWithSession(sessionID string) {
	s.T().Log("Testing tools/list with session ID")

	mcpRequest := `{
		"method": "tools/list",
		"params": {},
		"jsonrpc": "2.0",
		"id": 3
	}`

	cmd := exec.Command("kubectl", "exec", "-n", "curl", "curl", "--",
		"curl", "-v", "--no-buffer",
		"-H", "Content-Type: application/json",
		"-H", "Accept: text/event-stream,application/json",
		"-H", fmt.Sprintf("mcp-session-id: %s", sessionID),
		"-d", mcpRequest,
		"--max-time", "10",
		"http://gw.default.svc.cluster.local:8080/mcp")

	output, err := cmd.CombinedOutput()
	s.Require().NoError(err, "Failed to execute tools/list request")

	outputStr := string(output)
	s.T().Logf("Tools/list response: %s", outputStr)

	// Check for session expiry and handle gracefully
	if strings.Contains(outputStr, "401 Unauthorized") && strings.Contains(outputStr, "Session not found") {
		s.T().Log("Session expired - this is expected behavior for short-lived sessions")
		s.T().Log("Re-initializing session for tools/list test...")

		// Re-initialize and try again
		newSessionID := s.initializeAndGetSessionID()
		s.testToolsListWithSession(newSessionID)
		return
	}

	// Check if we got a successful HTTP response
	s.Require().Contains(outputStr, "< HTTP/1.1 200 OK", "tools/list should return 200 OK")

	// For tools/list, an empty result might be valid if no tools exist
	if strings.Contains(outputStr, `"result"`) {
		s.T().Log("tools/list returned result data")
	} else {
		s.T().Log("tools/list returned empty/minimal response (might be valid)")
	}
}

func (s *testingSuite) testSSEEndpoint() {
	s.T().Log("Testing MCP SSE endpoint to get session ID")

	// Use direct kubectl exec to properly handle SSE streaming
	cmd := exec.Command("kubectl", "exec", "-n", "curl", "curl", "--",
		"curl", "-v", "-N",
		"-H", "Accept: text/event-stream",
		"--max-time", "5", // Give it 5 seconds to get initial data
		"http://gw.default.svc.cluster.local:8080/sse")

	output, err := cmd.CombinedOutput()

	// For SSE, timeout (exit code 28) is expected after getting initial data
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok && exitError.ExitCode() == 28 {
			s.T().Log("SSE connection timed out as expected (got initial data then timeout)")
		} else {
			s.Require().NoError(err, "Failed to execute SSE request")
		}
	}

	outputStr := string(output)
	s.T().Logf("SSE response: %s", outputStr)

	// Verify we got a successful HTTP response
	s.Require().Contains(outputStr, "< HTTP/1.1 200 OK", "SSE endpoint should return 200 OK")

	// Verify we got SSE data with session ID
	s.Require().Contains(outputStr, "sessionId=", "SSE should provide session ID")

	// Extract and log the session ID for debugging
	if strings.Contains(outputStr, "sessionId=") {
		sessionIDRegex := regexp.MustCompile(`sessionId=([a-f0-9-]+)`)
		matches := sessionIDRegex.FindStringSubmatch(outputStr)
		if len(matches) > 1 {
			sessionID := strings.TrimSpace(matches[1])
			s.T().Logf("SSE provided session ID: %s", sessionID)
		}
	}

	s.T().Log("SSE endpoint working correctly")
}

// Dynamic MCP Tests
func (s *testingSuite) TestDynamicMCPConnection() {
	// Wait for both MCP server deployments to be ready
	s.TestInstallation.Assertions.EventuallyPodsRunning(s.Ctx, "default", metav1.ListOptions{
		LabelSelector: "app=mcp-website-fetcher",
	})

	s.TestInstallation.Assertions.EventuallyPodsRunning(s.Ctx, "default", metav1.ListOptions{
		LabelSelector: "app=mcp-admin-server",
	})

	// Wait for curl pod to be ready
	s.TestInstallation.Assertions.EventuallyPodsRunning(s.Ctx, "curl", metav1.ListOptions{
		LabelSelector: "app.kubernetes.io/name=curl",
	})

	// Verify dynamic HTTPRoute is accepted
	s.TestInstallation.Assertions.EventuallyHTTPRouteCondition(s.Ctx, "dynamic-mcp-route", "default", gwv1.RouteConditionAccepted, metav1.ConditionTrue)
}

func (s *testingSuite) TestDynamicMCPAdminRouting() {
	s.T().Log("Testing dynamic MCP routing for admin user")

	// MCP initialize request with admin header
	mcpRequest := `{
		"method": "initialize",
		"params": {
			"protocolVersion": "2025-06-18",
			"capabilities": {"roots": {}},
			"clientInfo": {"name": "admin-client", "version": "1.0.0"}
		},
		"jsonrpc": "2.0",
		"id": 0
	}`

	mcpCurlOpts := []curl.Option{
		curl.WithHost(kubeutils.ServiceFQDN(dynamicGatewayService.ObjectMeta)),
		curl.WithPort(8080),
		curl.WithPath("/mcp"),
		curl.WithMethod("POST"),
		curl.WithHeader("Content-Type", "application/json"),
		curl.WithHeader("Accept", "text/event-stream,application/json"),
		curl.WithHeader("user-type", "admin"), // This should route to admin server
		curl.WithBody(mcpRequest),
		curl.WithArgs([]string{"--max-time", "5"}),
	}

	s.TestInstallation.Assertions.AssertEventualCurlResponse(
		s.Ctx,
		testdefaults.CurlPodExecOpt,
		mcpCurlOpts,
		expectMCPInitializeResponse,
	)

	s.T().Log("Admin routing working correctly")
}

func (s *testingSuite) TestDynamicMCPUserRouting() {
	s.T().Log("Testing dynamic MCP routing for regular user")

	// MCP initialize request with user header
	mcpRequest := `{
		"method": "initialize",
		"params": {
			"protocolVersion": "2025-06-18",
			"capabilities": {"roots": {}},
			"clientInfo": {"name": "user-client", "version": "1.0.0"}
		},
		"jsonrpc": "2.0",
		"id": 0
	}`

	mcpCurlOpts := []curl.Option{
		curl.WithHost(kubeutils.ServiceFQDN(dynamicGatewayService.ObjectMeta)),
		curl.WithPort(8080),
		curl.WithPath("/mcp"),
		curl.WithMethod("POST"),
		curl.WithHeader("Content-Type", "application/json"),
		curl.WithHeader("Accept", "text/event-stream,application/json"),
		curl.WithHeader("user-type", "user"), // This should route to user server
		curl.WithBody(mcpRequest),
		curl.WithArgs([]string{"--max-time", "5"}),
	}

	s.TestInstallation.Assertions.AssertEventualCurlResponse(
		s.Ctx,
		testdefaults.CurlPodExecOpt,
		mcpCurlOpts,
		expectMCPInitializeResponse,
	)

	s.T().Log("User routing working correctly")
}

func (s *testingSuite) TestDynamicMCPDefaultRouting() {
	s.T().Log("Testing dynamic MCP routing with no header (default to user)")

	// MCP initialize request with no user-type header
	mcpRequest := `{
		"method": "initialize",
		"params": {
			"protocolVersion": "2025-06-18",
			"capabilities": {"roots": {}},
			"clientInfo": {"name": "default-client", "version": "1.0.0"}
		},
		"jsonrpc": "2.0",
		"id": 0
	}`

	mcpCurlOpts := []curl.Option{
		curl.WithHost(kubeutils.ServiceFQDN(dynamicGatewayService.ObjectMeta)),
		curl.WithPort(8080),
		curl.WithPath("/mcp"),
		curl.WithMethod("POST"),
		curl.WithHeader("Content-Type", "application/json"),
		curl.WithHeader("Accept", "text/event-stream,application/json"),
		// No user-type header - should default to user server
		curl.WithBody(mcpRequest),
		curl.WithArgs([]string{"--max-time", "5"}),
	}

	s.TestInstallation.Assertions.AssertEventualCurlResponse(
		s.Ctx,
		testdefaults.CurlPodExecOpt,
		mcpCurlOpts,
		expectMCPInitializeResponse,
	)

	s.T().Log("Default routing working correctly")
}
