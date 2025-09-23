package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
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

const mcpProto = "2025-03-26"

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
			"protocolVersion": "2025-03-26",
			"capabilities": {"roots": {}},
			"clientInfo": {"name": "test-client", "version": "1.0.0"}
		},
		"jsonrpc": "2.0",
		"id": 1
	}`

	headers := map[string]string{
		"Content-Type":         "application/json",
		"Accept":               "application/json, text/event-stream",
		"MCP-Protocol-Version": mcpProto,
	}
	outputStr, err := s.execCurlMCP(8080, headers, mcpRequest, "--max-time", "20")
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
		s.notifyInitialized(sessionID)
		return sessionID
	}

	s.T().Fatal("Could not extract session ID from initialize response")
	return ""
}

func (s *testingSuite) testResourcesListWithSession(sessionID string) {
	s.T().Log("Testing resources/list with session ID")

	mcpRequest := `{
		      "method": "resources/list",
		      "params": { "_meta": { "progressToken": 1 } },
		      "jsonrpc": "2.0",
		      "id": 2
		    }`

	headers := map[string]string{
		"Content-Type":         "application/json",
		"Accept":               "application/json, text/event-stream",
		"mcp-session-id":       sessionID,
		"MCP-Protocol-Version": mcpProto,
	}

	// Ask curl to stream (-N) so SSE arrives immediately
	out, err := s.execCurlMCP(8080, headers, mcpRequest, "-N", "--max-time", "10")
	s.Require().NoError(err, "resources/list curl failed")
	// Check if we got a 401 (session expired)
	if strings.Contains(out, "401 Unauthorized") && strings.Contains(out, "Session not found") {
		s.T().Log("Session expired, re-initializing...")
		newSessionID := s.initializeAndGetSessionID()
		headers["mcp-session-id"] = newSessionID
		out, err = s.execCurlMCP(8080, headers, mcpRequest, "-N", "--max-time", "10")
		s.Require().NoError(err, "resources/list retry after re-init failed")
	}
	s.requireHTTPStatus(out, 200)

	// Extract first SSE data payload
	payload, ok := FirstSSEDataPayload(out)
	if !ok {
		s.T().Log("No SSE payload from resources/list; retrying once with same session")
		out, err = s.execCurlMCP(8080, headers, mcpRequest, "-N", "--max-time", "10")
		s.Require().NoError(err, "resources/list retry curl failed")
		s.requireHTTPStatus(out, 200)
		payload, ok = FirstSSEDataPayload(out)
	}
	s.Require().True(ok, "expected SSE data payload in resources/list (after retry)")

	s.T().Logf("resources/list payload: %s", payload)
	s.Require().True(IsJSONValid(payload), "resources/list SSE payload is not valid JSON")

	var resp ResourcesListResponse
	_ = json.Unmarshal([]byte(payload), &resp)

	if resp.Error != nil {
		s.T().Logf("resources/list error: %d %s", resp.Error.Code, resp.Error.Message)
		s.FailNow("resources/list returned error")
	}

	// Not all servers expose resources; we just assert the structure is present.
	s.Require().NotNil(resp.Result, "resources/list missing result")
	s.T().Logf("resources: %d", len(resp.Result.Resources))
}

func (s *testingSuite) testToolsListWithSession(sessionID string) {
	s.T().Log("Testing tools/list with session ID")

	mcpRequest := `{
	  "method": "tools/list",
      "params": {"_meta": {"progressToken": 1}},
	  "jsonrpc": "2.0",
	  "id": 3
	}`

	headers := map[string]string{
		"Content-Type":         "application/json",
		"Accept":               "application/json, text/event-stream",
		"mcp-session-id":       sessionID,
		"MCP-Protocol-Version": mcpProto,
	}
	out, err := s.execCurlMCP(8080, headers, mcpRequest, "-N", "--max-time", "10")
	s.Require().NoError(err, "tools/list curl failed")

	// If session was replaced, some gateways emit a JSON error as SSE payload (HTTP 200).
	// So parse SSE first, then decide.
	payload, ok := FirstSSEDataPayload(out)
	if !ok {
		s.T().Log("No SSE payload from tools/list; sending notifications/initialized and retrying once")
		s.notifyInitialized(sessionID)
		out, err = s.execCurlMCP(8080, headers, mcpRequest, "-N", "--max-time", "10")
		s.Require().NoError(err, "tools/list retry curl failed")
		s.requireHTTPStatus(out, 200)
		payload, ok = FirstSSEDataPayload(out)
	}
	s.Require().True(ok, "expected SSE data payload in tools/list (after retry)")
	s.Require().True(IsJSONValid(payload), "tools/list SSE payload is not valid JSON")

	var resp ToolsListResponse
	_ = json.Unmarshal([]byte(payload), &resp)

	if resp.Error != nil && strings.Contains(resp.Error.Message, "Session not found") {
		// Re-init and retry once
		s.T().Log("Session expired; re-initializing and retrying tools/list")
		newID := s.initializeAndGetSessionID()
		s.testToolsListWithSession(newID)
		return
	}

	s.requireHTTPStatus(out, 200)
	s.Require().NotNil(resp.Result, "tools/list missing result")
	s.T().Logf("tools: %d", len(resp.Result.Tools))
	// If you expect at least one tool:
	s.Require().GreaterOrEqual(len(resp.Result.Tools), 1, "expected at least one tool")
}

// notifyInitialized sends the "notifications/initialized" message once for a session.
func (s *testingSuite) notifyInitialized(sessionID string) {
	mcpRequest := `{"jsonrpc":"2.0","method":"notifications/initialized"}`
	headers := map[string]string{
		"Content-Type":         "application/json",
		"Accept":               "application/json, text/event-stream",
		"mcp-session-id":       sessionID,
		"MCP-Protocol-Version": mcpProto,
	}
	// We don't care about the body; just make sure it doesn't 401.
	out, _ := s.execCurlMCP(8080, headers, mcpRequest, "-N", "--max-time", "2")
	if strings.Contains(out, "401 Unauthorized") {
		s.T().Log("notifyInitialized hit 401; session likely already GC’d")
	}
}

// helper to run a request via curl pod to a given path and return combined output
func (s *testingSuite) execCurl(port int, path string, headers map[string]string, body string, extraArgs ...string) (string, error) {
	args := []string{"exec", "-n", "curl", "curl", "--", "curl", "-v", "-N", "--http1.1"}
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
			"protocolVersion": "2025-03-26",
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
			"protocolVersion": "2025-03-26",
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
			"protocolVersion": "2025-03-26",
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

// ExtractMCPSessionID finds the mcp-session-id header value in a verbose curl output.
func ExtractMCPSessionID(out string) string {
	re := regexp.MustCompile(`(?i)mcp-session-id:\s*([a-f0-9-]+)`)
	m := re.FindStringSubmatch(out)
	if len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

// FirstSSEDataPayload returns the first full SSE "data:" event payload (coalescing multi-line data:)
// from a verbose curl output or raw SSE stream.
func FirstSSEDataPayload(out string) (string, bool) {
	sc := bufio.NewScanner(strings.NewReader(out))
	var buf bytes.Buffer
	got := false
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "data:") {
			got = true
			payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			if buf.Len() > 0 {
				buf.WriteByte('\n')
			}
			buf.WriteString(payload)
			continue
		}
		// Blank line after we started -> end of this SSE event
		if got && strings.TrimSpace(line) == "" {
			break
		}
	}
	s := strings.TrimSpace(buf.String())
	if s == "" {
		return "", false
	}
	return s, true
}

// IsJSONValid is a small helper to check the payload is valid JSON
func IsJSONValid(s string) bool {
	var js json.RawMessage
	return json.Unmarshal([]byte(s), &js) == nil
}

type ToolsListResponse struct {
	JSONRPC string `json:"jsonrpc"`
	Result  *struct {
		Tools []struct {
			Name        string `json:"name"`
			Description string `json:"description,omitempty"`
		} `json:"tools"`
	} `json:"result,omitempty"`
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

type ResourcesListResponse struct {
	JSONRPC string `json:"jsonrpc"`
	Result  *struct {
		Resources []struct {
			URI  string `json:"uri"`
			Name string `json:"name,omitempty"`
		} `json:"resources"`
	} `json:"result,omitempty"`
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}
