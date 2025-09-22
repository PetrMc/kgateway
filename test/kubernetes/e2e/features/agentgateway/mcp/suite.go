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

	"github.com/kgateway-dev/kgateway/v2/test/kubernetes/e2e"
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

	headers := map[string]string{
		"Content-Type": "application/json",
		"Accept":       "text/event-stream,application/json",
	}
	outputStr, err := s.execCurlMCP(8080, headers, mcpRequest, "--max-time", "10")
	s.Require().NoError(err, "Failed to execute initialize request")
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

	headers := map[string]string{
		"Content-Type":   "application/json",
		"Accept":         "text/event-stream,application/json",
		"mcp-session-id": sessionID,
	}
	outputStr, err := s.execCurlMCP(8080, headers, mcpRequest, "--no-buffer", "--max-time", "10")
	s.Require().NoError(err, "Failed to execute resources/list request")
	s.T().Logf("Resources/list response: %s", outputStr)

	// Check if we got a successful HTTP response
	s.requireHTTPStatus(outputStr, 200)

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

	headers := map[string]string{
		"Content-Type":   "application/json",
		"Accept":         "text/event-stream,application/json",
		"mcp-session-id": sessionID,
	}
	outputStr, err := s.execCurlMCP(8080, headers, mcpRequest, "--no-buffer", "--max-time", "10")
	s.Require().NoError(err, "Failed to execute tools/list request")
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
	s.requireHTTPStatus(outputStr, 200)

	// For tools/list, an empty result might be valid if no tools exist
	if strings.Contains(outputStr, `"result"`) {
		s.T().Log("tools/list returned result data")
	} else {
		s.T().Log("tools/list returned empty/minimal response (might be valid)")
	}
}

func (s *testingSuite) TestSSEEndpoint() {
	s.T().Log("Testing MCP SSE endpoint to get session ID")

	// Use shared curl helper to properly handle SSE streaming
	headers := map[string]string{
		"Accept": "text/event-stream",
	}
	outputStr, err := s.execCurl(8080, "/sse", headers, "", "-N", "--max-time", "5")
	// For SSE, timeout (exit code 28) is expected after getting initial data
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok && exitError.ExitCode() == 28 {
			s.T().Log("SSE connection timed out as expected (got initial data then timeout)")
		} else {
			s.Require().NoError(err, "Failed to execute SSE request")
		}
	}

	s.T().Logf("SSE response: %s", outputStr)

	// Verify we got a successful HTTP response
	s.requireHTTPStatus(outputStr, 200)

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

// helper to run a request via curl pod to a given path and return combined output
func (s *testingSuite) execCurl(port int, path string, headers map[string]string, body string, extraArgs ...string) (string, error) {
	args := []string{"exec", "-n", "curl", "curl", "--", "curl", "-v"}
	for k, v := range headers {
		args = append(args, "-H", fmt.Sprintf("%s: %s", k, v))
	}
	if body != "" {
		args = append(args, "-d", body)
	}
	args = append(args, extraArgs...)
	args = append(args, fmt.Sprintf("http://gw.default.svc.cluster.local:%d%s", port, path))

	cmd := exec.Command("kubectl", args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// helper to run a POST to /mcp with optional headers and body via curl pod and return combined output
func (s *testingSuite) execCurlMCP(port int, headers map[string]string, body string, extraArgs ...string) (string, error) {
	return s.execCurl(port, "/mcp", headers, body, extraArgs...)
}

// helper to assert HTTP status from verbose curl output (supports HTTP/1.1 and HTTP/2)
func (s *testingSuite) requireHTTPStatus(out string, code int) {
	re := regexp.MustCompile(fmt.Sprintf(`(?m)^< HTTP/\S+\s+%d\b`, code))
	s.Require().True(re.FindStringIndex(out) != nil, "expected HTTP %d; got:\n%s", code, out)
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

	headers := map[string]string{
		"Content-Type": "application/json",
		"Accept":       "text/event-stream,application/json",
		"user-type":    "admin",
	}
	outputStr, err := s.execCurlMCP(8080, headers, mcpRequest, "--max-time", "5")
	s.Require().NoError(err, "Failed to execute admin initialize request")
	s.requireHTTPStatus(outputStr, 200)

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

	headers := map[string]string{
		"Content-Type": "application/json",
		"Accept":       "text/event-stream,application/json",
		"user-type":    "user",
	}
	outputStr, err := s.execCurlMCP(8080, headers, mcpRequest, "--max-time", "5")
	s.Require().NoError(err, "Failed to execute user initialize request")
	s.requireHTTPStatus(outputStr, 200)

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

	headers := map[string]string{
		"Content-Type": "application/json",
		"Accept":       "text/event-stream,application/json",
	}
	outputStr, err := s.execCurlMCP(8080, headers, mcpRequest, "--max-time", "5")
	s.Require().NoError(err, "Failed to execute default initialize request")
	s.requireHTTPStatus(outputStr, 200)

	s.T().Log("Default routing working correctly")
}
