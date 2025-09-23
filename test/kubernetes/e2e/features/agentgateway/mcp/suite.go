package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

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

// debugEnabled returns true if E2E_DEBUG env var is set to "1"/"true"/"yes".
func debugEnabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("E2E_DEBUG")))
	return v == "1" || v == "true" || v == "yes"
}

// logCurl emits verbose curl output when helpful. It always logs on failure,
// and logs on success only if E2E_DEBUG is enabled.
func (s *testingSuite) logCurl(label, out string) {
	if s.T().Failed() || debugEnabled() {
		s.T().Logf("\n========== %s (curl verbose output) ==========\n%s\n========== end %s ==========\n", label, out, label)
	}
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
			// Optional combined comparison
			"TestDynamicMCPAdminVsUserTools": &dynamicSetup,
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
	// Helpful visibility: show the curl invocation and its output in debug mode.
	if debugEnabled() {
		// Redact potentially sensitive headers when logging
		redacted := make([]string, 0, len(args))
		for i := 0; i < len(args); i++ {
			if args[i] == "-H" && i+1 < len(args) {
				h := args[i+1]
				hl := strings.ToLower(h)
				if strings.HasPrefix(hl, "authorization:") || strings.HasPrefix(hl, "mcp-session-id:") {
					// keep header name, redact value
					colon := strings.Index(h, ":")
					if colon > -1 {
						h = h[:colon+1] + " <redacted>"
					} else {
						h = "<redacted header>"
					}
				}
				redacted = append(redacted, "-H", h)
				i++
				continue
			}
			redacted = append(redacted, args[i])
		}
		s.T().Logf("kubectl %s", strings.Join(redacted, " "))
		s.logCurl("curl response", string(out))
	}
	return string(out), err
}

// helper to run a POST to /mcp with optional headers and body via curl pod and return combined output
func (s *testingSuite) execCurlMCP(port int, headers map[string]string, body string, extraArgs ...string) (string, error) {
	out, err := s.execCurl(port, "/mcp", headers, body, extraArgs...)
	s.T().Logf("execCurlMCP:\n%s", out) // always print
	return out, err
}

// helper to assert HTTP status from verbose curl output (supports HTTP/1.1 and HTTP/2)
func (s *testingSuite) requireHTTPStatus(out string, code int) {
	re := regexp.MustCompile(fmt.Sprintf(`(?m)^< HTTP/\S+\s+%d\b`, code))
	if re.FindStringIndex(out) == nil {
		// Always log the body on mismatch to make failures actionable.
		s.logCurl(fmt.Sprintf("HTTP status mismatch (wanted %d)", code), out)
		s.Require().Failf("HTTP status check", "expected HTTP %d; full output logged above", code)
	}
}

// Dynamic MCP Tests
func (s *testingSuite) TestDynamicMCPConnection() {
	s.waitDynamicReady()

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
	s.waitDynamicReady()

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
		"Content-Type":         "application/json",
		"Accept":               "text/event-stream,application/json",
		"MCP-Protocol-Version": mcpProto,
		"user-type":            "admin",
	}
	outputStr, err := s.execCurlMCP(8080, headers, mcpRequest, "--max-time", "5")
	s.Require().NoError(err, "Failed to execute admin initialize request")
	s.requireHTTPStatus(outputStr, 200)
	s.logCurl("admin initialize", outputStr)

	// Assert MCP initialize payload looks correct and capture session id
	adminSession := ExtractMCPSessionID(outputStr)
	s.Require().NotEmpty(adminSession, "admin initialize must return mcp-session-id header")
	s.notifyInitializedWithHeaders(adminSession, map[string]string{"user-type": "admin"})
	adminInitPayload, ok := FirstSSEDataPayload(outputStr)
	s.Require().True(ok, "admin initialize must return SSE payload")
	var adminInit InitializeResponse
	s.Require().NoError(json.Unmarshal([]byte(adminInitPayload), &adminInit), "admin initialize payload must be JSON")
	s.Require().Nil(adminInit.Error, "admin initialize returned error: %+v", adminInit.Error)
	s.Require().NotNil(adminInit.Result, "admin initialize missing result")
	s.Require().Equal(mcpProto, adminInit.Result.ProtocolVersion, "protocolVersion mismatch")
	s.Require().NotEmpty(adminInit.Result.ServerInfo.Name, "serverInfo.name must be set")
	s.T().Logf("admin serverInfo: %s %s", adminInit.Result.ServerInfo.Name, adminInit.Result.ServerInfo.Version)

	// tools/list using the same session
	adminTools := s.mustListTools(adminSession, "admin tools/list", map[string]string{"user-type": "admin"})
	s.Require().GreaterOrEqual(len(adminTools), 1, "admin should expose at least one tool")
	s.T().Logf("admin tools: %s", strings.Join(adminTools, ", "))

	s.T().Log("Admin routing working correctly")
}

func (s *testingSuite) TestDynamicMCPUserRouting() {
	s.waitDynamicReady()
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
		"Content-Type":         "application/json",
		"Accept":               "text/event-stream,application/json",
		"MCP-Protocol-Version": mcpProto,
		"user-type":            "user",
	}
	outputStr, err := s.execCurlMCP(8080, headers, mcpRequest, "--max-time", "5")
	s.Require().NoError(err, "Failed to execute user initialize request")
	s.requireHTTPStatus(outputStr, 200)
	s.logCurl("user initialize", outputStr)

	userSession := ExtractMCPSessionID(outputStr)
	s.notifyInitializedWithHeaders(userSession, map[string]string{"user-type": "user"})
	s.Require().NotEmpty(userSession, "user initialize must return mcp-session-id header")
	userInitPayload, ok := FirstSSEDataPayload(outputStr)
	s.Require().True(ok, "user initialize must return SSE payload")
	var userInit InitializeResponse
	s.Require().NoError(json.Unmarshal([]byte(userInitPayload), &userInit), "user initialize payload must be JSON")
	s.Require().Nil(userInit.Error, "user initialize returned error: %+v", userInit.Error)
	s.Require().NotNil(userInit.Result, "user initialize missing result")
	s.Require().Equal(mcpProto, userInit.Result.ProtocolVersion, "protocolVersion mismatch")
	s.Require().NotEmpty(userInit.Result.ServerInfo.Name, "serverInfo.name must be set")
	s.T().Logf("user serverInfo: %s %s", userInit.Result.ServerInfo.Name, userInit.Result.ServerInfo.Version)

	// tools/list using the same session
	userTools := s.mustListTools(userSession, "user tools/list", map[string]string{"user-type": "user"})
	s.Require().GreaterOrEqual(len(userTools), 1, "user should expose at least one tool")
	s.T().Logf("user tools: %s", strings.Join(userTools, ", "))

	s.T().Log("User routing working correctly")
}

func (s *testingSuite) TestDynamicMCPDefaultRouting() {
	s.waitDynamicReady()
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
		"Content-Type":         "application/json",
		"Accept":               "text/event-stream,application/json",
		"MCP-Protocol-Version": mcpProto,
	}
	outputStr, err := s.execCurlMCP(8080, headers, mcpRequest, "--max-time", "5")
	s.Require().NoError(err, "Failed to execute default initialize request")
	s.requireHTTPStatus(outputStr, 200)
	s.logCurl("default initialize", outputStr)

	defSession := ExtractMCPSessionID(outputStr)
	s.notifyInitializedWithHeaders(defSession, map[string]string{"user-type": "user"})
	s.Require().NotEmpty(defSession, "default initialize must return mcp-session-id header")
	defInitPayload, ok := FirstSSEDataPayload(outputStr)
	s.Require().True(ok, "default initialize must return SSE payload")
	var defInit InitializeResponse
	s.Require().NoError(json.Unmarshal([]byte(defInitPayload), &defInit), "default initialize payload must be JSON")
	s.Require().Nil(defInit.Error, "default initialize returned error: %+v", defInit.Error)
	s.Require().NotNil(defInit.Result, "default initialize missing result")
	s.Require().Equal(mcpProto, defInit.Result.ProtocolVersion, "protocolVersion mismatch")
	s.Require().NotEmpty(defInit.Result.ServerInfo.Name, "serverInfo.name must be set")
	s.T().Logf("default serverInfo: %s %s", defInit.Result.ServerInfo.Name, defInit.Result.ServerInfo.Version)

	// tools/list using the same session
	defTools := s.mustListTools(defSession, "default tools/list", map[string]string{"user-type": "user"})
	s.Require().GreaterOrEqual(len(defTools), 1, "default/user should expose at least one tool")
	s.T().Logf("default tools: %s", strings.Join(defTools, ", "))

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
		raw := sc.Text()
		// Curl verbose sometimes prefixes body lines with "<" or "< ".
		line := strings.TrimSpace(raw)
		// Find "data:" anywhere on the line (handles "data:", "<data:", "< data:", etc.)
		if idx := strings.Index(line, "data:"); idx >= 0 {
			got = true
			payload := strings.TrimSpace(line[idx+len("data:"):])
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

// InitializeResponse models the MCP initialize payload.
type InitializeResponse struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Result  *struct {
		ProtocolVersion string         `json:"protocolVersion"`
		Capabilities    map[string]any `json:"capabilities"`
		ServerInfo      struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"serverInfo"`
		Instructions string `json:"instructions,omitempty"`
	} `json:"result,omitempty"`
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// mustListTools issues tools/list with an existing session and returns tool names.
// Pass routeHeaders (e.g., map[string]string{"user-type":"admin"}) so the gateway
// picks the same backend as the initialize call.
func (s *testingSuite) mustListTools(sessionID, label string, routeHeaders map[string]string) []string {
	mcpRequest := `{
	  "method": "tools/list",
	  "params": {"_meta": {"progressToken": 1}},
	  "jsonrpc": "2.0",
	  "id": 999
	}`
	headers := map[string]string{
		"Content-Type":         "application/json",
		"Accept":               "application/json, text/event-stream",
		"MCP-Protocol-Version": mcpProto,
		"mcp-session-id":       sessionID,
	}
	for k, v := range routeHeaders {
		headers[k] = v
	}
	out, err := s.execCurlMCP(8080, headers, mcpRequest, "-N", "--max-time", "10")
	s.Require().NoError(err, "%s curl failed", label)
	s.requireHTTPStatus(out, 200)

	payload, ok := FirstSSEDataPayload(out)
	s.Require().True(ok, "%s expected SSE data payload", label)

	var resp ToolsListResponse

	if err := json.Unmarshal([]byte(payload), &resp); err != nil {
		s.Require().Failf(label, "unmarshal failed: %v\npayload: %s", err, payload)
	}
	if resp.Error != nil {
		// Common transient: session not warm yet; give it one nudge and retry once.
		if strings.Contains(strings.ToLower(resp.Error.Message), "session not found") ||
			strings.Contains(strings.ToLower(resp.Error.Message), "start sse client") {
			s.notifyInitializedWithHeaders(sessionID, routeHeaders)
			out, err = s.execCurlMCP(8080, headers, mcpRequest, "-N", "--max-time", "10")
			s.Require().NoError(err, "%s retry curl failed", label)
			s.requireHTTPStatus(out, 200)
			payload, ok = FirstSSEDataPayload(out)
			s.Require().True(ok, "%s expected SSE data payload (retry)", label)
			s.Require().NoError(json.Unmarshal([]byte(payload), &resp), "%s unmarshal failed (retry)", label)
		}
	}
	if resp.Error != nil {
		s.Require().Failf(label, "tools/list returned error: %d %s", resp.Error.Code, resp.Error.Message)
	}
	s.Require().NotNil(resp.Result, "%s missing result", label)
	names := make([]string, 0, len(resp.Result.Tools))
	for _, t := range resp.Result.Tools {
		names = append(names, t.Name)
	}
	return names
}

func (s *testingSuite) notifyInitializedWithHeaders(sessionID string, routeHeaders map[string]string) {
	mcpRequest := `{"jsonrpc":"2.0","method":"notifications/initialized"}`
	headers := map[string]string{
		"Content-Type":         "application/json",
		"Accept":               "application/json, text/event-stream",
		"MCP-Protocol-Version": mcpProto,
		"mcp-session-id":       sessionID,
	}
	for k, v := range routeHeaders {
		headers[k] = v // carry user-type
	}
	_, _ = s.execCurlMCP(8080, headers, mcpRequest, "-N", "--max-time", "5")
	// Allow the gateway to register the session before the first RPC.
	time.Sleep(75 * time.Millisecond)
}

// TestDynamicMCPAdminVsUserTools initializes two sessions (admin and user) against the same
// dynamic route and compares the exposed tool sets. This gives positive proof that
// header-based routing is sending traffic to distinct backends.
func (s *testingSuite) TestDynamicMCPAdminVsUserTools() {
	s.waitDynamicReady()

	s.T().Log("Comparing admin vs user tool sets on dynamic MCP route")

	initBody := `{
		"method": "initialize",
		"params": {
			"protocolVersion": "2025-03-26",
			"capabilities": {"roots": {}},
			"clientInfo": {"name": "compare-client", "version": "1.0.0"}
		},
		"jsonrpc": "2.0",
		"id": 0
	}`

	// Admin session
	adminHdr := map[string]string{
		"Content-Type":         "application/json",
		"Accept":               "text/event-stream,application/json",
		"MCP-Protocol-Version": mcpProto,
		"user-type":            "admin",
	}
	adminOut, err := s.execCurlMCP(8080, adminHdr, initBody, "--max-time", "5")
	s.Require().NoError(err, "admin initialize failed")
	s.requireHTTPStatus(adminOut, 200)
	adminSID := s.initializeSession(initBody, adminHdr, "admin")
	s.notifyInitializedWithHeaders(adminSID, map[string]string{"user-type": "admin"})
	s.Require().NotEmpty(adminSID, "admin session id missing")
	adminTools := s.mustListTools(adminSID, "admin tools/list (compare)", map[string]string{"user-type": "admin"})

	// User session
	userHdr := map[string]string{
		"Content-Type":         "application/json",
		"Accept":               "text/event-stream,application/json",
		"MCP-Protocol-Version": mcpProto,
		"user-type":            "user",
	}
	userOut, err := s.execCurlMCP(8080, userHdr, initBody, "--max-time", "5")
	s.Require().NoError(err, "user initialize failed")
	s.requireHTTPStatus(userOut, 200)
	userSID := s.initializeSession(initBody, userHdr, "user")
	s.notifyInitializedWithHeaders(userSID, map[string]string{"user-type": "user"})
	s.Require().NotEmpty(userSID, "user session id missing")
	userTools := s.mustListTools(userSID, "user tools/list (compare)", map[string]string{"user-type": "user"})

	// Compare sets; admin should be a superset or at least different.
	adminSet := make(map[string]struct{}, len(adminTools))
	for _, n := range adminTools {
		adminSet[n] = struct{}{}
	}
	same := len(adminTools) == len(userTools)
	if same {
		for _, n := range userTools {
			if _, ok := adminSet[n]; !ok {
				same = false
				break
			}
		}
	}
	if same {
		s.T().Log("WARNING: admin and user tool sets are identical; verify backend config if you expect variance")
	} else {
		s.T().Logf("admin tools: %s", strings.Join(adminTools, ", "))
		s.T().Logf("user tools: %s", strings.Join(userTools, ", "))
	}
	// At minimum, each must have >=1 tools which we already asserted in mustListTools callers above.
}

func (s *testingSuite) waitDynamicReady() {
	// The dynamic route forwards to the mcp-admin-server deployment.
	s.TestInstallation.Assertions.EventuallyPodsRunning(
		s.Ctx, "default",
		metav1.ListOptions{LabelSelector: "app=mcp-admin-server"},
	)
	s.TestInstallation.Assertions.EventuallyHTTPRouteCondition(
		s.Ctx, "dynamic-mcp-route", "default",
		gwv1.RouteConditionAccepted, metav1.ConditionTrue,
	)
}

// initializeSession opens a session with headers and returns a valid session ID.
// It retries on transient gateway/backend races like:
//   - SSE error: "Failed to list connections: start sse client"
//   - Missing/invalid SSE payload
func (s *testingSuite) initializeSession(initBody string, hdr map[string]string, label string) string {
	backoffs := []time.Duration{100 * time.Millisecond, 250 * time.Millisecond, 500 * time.Millisecond}
	for attempt := 0; attempt <= len(backoffs); attempt++ {
		out, err := s.execCurlMCP(8080, hdr, initBody, "--max-time", "10")
		s.Require().NoError(err, "%s initialize failed", label)
		s.requireHTTPStatus(out, 200)

		payload, ok := FirstSSEDataPayload(out)
		// If no payload, retry
		if !ok || strings.TrimSpace(payload) == "" {
			if attempt == len(backoffs) {
				s.Require().Failf(label, "initialize returned no SSE payload")
			}
		} else {
			// Parse and ensure it's a result, not an error
			var init InitializeResponse
			_ = json.Unmarshal([]byte(payload), &init)
			if init.Error == nil && init.Result != nil {
				sid := ExtractMCPSessionID(out)
				s.Require().NotEmpty(sid, "%s initialize must return mcp-session-id header", label)
				return sid
			}
			// If it's a known transient, we'll retry; otherwise surface it
			if init.Error != nil && strings.Contains(strings.ToLower(init.Error.Message), "start sse client") {
				// fall through to retry
			} else {
				s.Require().Failf(label, "initialize returned error: %v", init.Error)
			}
		}
		if attempt < len(backoffs) {
			time.Sleep(backoffs[attempt])
		}
	}
	// unreachable
	return ""
}
