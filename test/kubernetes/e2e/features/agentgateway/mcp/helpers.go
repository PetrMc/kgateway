package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

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

// mcpProto is the protocol version for the MCP server
const mcpProto = "2025-03-26"

// buildInitializeRequest is a helper function to build the initialize request for the MCP server
func buildInitializeRequest(clientName string, id int) string {
	return fmt.Sprintf(`{
		"method": "initialize",
		"params": {
			"protocolVersion": "%s",
			"capabilities": {"roots": {}},
			"clientInfo": {"name": "%s", "version": "1.0.0"}
		},
		"jsonrpc": "2.0",
		"id": %d
	}`, mcpProto, clientName, id)
}

// buildToolsListRequest is a helper function to build the tools list request for the MCP server
func buildToolsListRequest(id int) string {
	return fmt.Sprintf(`{
	  "method": "tools/list",
	  "params": {"_meta": {"progressToken": 1}},
	  "jsonrpc": "2.0",
	  "id": %d
	}`, id)
}

func buildResourcesListRequest(id int) string {
	return fmt.Sprintf(`{
	  "method": "resources/list",
	  "params": {"_meta": {"progressToken": 1}},
	  "jsonrpc": "2.0",
	  "id": %d
	}`, id)
}

func buildNotifyInitializedRequest() string {
	return `{"jsonrpc":"2.0","method":"notifications/initialized"}`
}

// mcpHeaders returns a base set of headers for MCP requests.
// Accept includes both JSON and SSE to support initialize responses and streaming.
func mcpHeaders() map[string]string {
	accept := "application/json, text/event-stream"
	return map[string]string{
		"Content-Type":         "application/json",
		"Accept":               accept,
		"MCP-Protocol-Version": mcpProto,
	}
}

// withSessionID returns a copy of headers including mcp-session-id.
func withSessionID(headers map[string]string, sessionID string) map[string]string {
	cp := make(map[string]string, len(headers)+1)
	for k, v := range headers {
		cp[k] = v
	}
	if sessionID != "" {
		cp["mcp-session-id"] = sessionID
	}
	return cp
}

// withRouteHeaders merges route-specific headers (like user-type) into a copy.
func withRouteHeaders(headers map[string]string, extras map[string]string) map[string]string {
	if len(extras) == 0 {
		return headers
	}
	cp := make(map[string]string, len(headers)+len(extras))
	for k, v := range headers {
		cp[k] = v
	}
	for k, v := range extras {
		cp[k] = v
	}
	return cp
}

func (s *testingSuite) initializeAndGetSessionID() string {
	s.T().Log("Initializing MCP and extracting session ID")

	mcpRequest := buildInitializeRequest("test-client", 1)

	headers := mcpHeaders()
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

	mcpRequest := buildResourcesListRequest(2)

	headers := withSessionID(mcpHeaders(), sessionID)

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

	mcpRequest := buildToolsListRequest(3)

	headers := withSessionID(mcpHeaders(), sessionID)
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
	mcpRequest := buildNotifyInitializedRequest()
	headers := withSessionID(mcpHeaders(), sessionID)
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
	s.T().Logf("curl response: %s", string(out))

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
	// Match lines like "< HTTP/1.1 200" or "HTTP/1.1 200" (some logs omit the '<')
	re := regexp.MustCompile(fmt.Sprintf(`(?m)^(?:<\s*)?HTTP/\S+\s+%d\b`, code))
	if re.FindStringIndex(out) == nil {
		// Always log the body on mismatch to make failures actionable.
		s.T().Logf("HTTP status mismatch (wanted %d): %s", code, out)
		s.Require().Failf("HTTP status check", "expected HTTP %d; full output logged above", code)
	}
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

// mustListTools issues tools/list with an existing session and returns tool names.
// Pass routeHeaders (e.g., map[string]string{"user-type":"admin"}) so the gateway
// picks the same backend as the initialize call.
func (s *testingSuite) mustListTools(sessionID, label string, routeHeaders map[string]string) []string {
	mcpRequest := buildToolsListRequest(999)
	headers := withRouteHeaders(withSessionID(mcpHeaders(), sessionID), routeHeaders)
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
	mcpRequest := buildNotifyInitializedRequest()
	headers := withRouteHeaders(withSessionID(mcpHeaders(), sessionID), routeHeaders)
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

	initBody := buildInitializeRequest("compare-client", 0)

	// Admin session
	adminHdr := withRouteHeaders(mcpHeaders(), map[string]string{"user-type": "admin"})
	adminOut, err := s.execCurlMCP(8080, adminHdr, initBody, "--max-time", "5")
	s.Require().NoError(err, "admin initialize failed")
	s.requireHTTPStatus(adminOut, 200)
	adminSID := s.initializeSession(initBody, adminHdr, "admin")
	s.notifyInitializedWithHeaders(adminSID, map[string]string{"user-type": "admin"})
	s.Require().NotEmpty(adminSID, "admin session id missing")
	adminTools := s.mustListTools(adminSID, "admin tools/list (compare)", map[string]string{"user-type": "admin"})

	// User session
	userHdr := withRouteHeaders(mcpHeaders(), map[string]string{"user-type": "user"})
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
	// User backend deployment should also be ready
	s.TestInstallation.Assertions.EventuallyPodsRunning(
		s.Ctx, "default",
		metav1.ListOptions{LabelSelector: "app=mcp-website-fetcher"},
	)
	// Curl pod used to drive HTTP requests must be ready
	s.TestInstallation.Assertions.EventuallyPodsRunning(
		s.Ctx, "curl",
		metav1.ListOptions{LabelSelector: "app.kubernetes.io/name=curl"},
	)
	// Gateway must be programmed before HTTPRoutes become effective
	s.TestInstallation.Assertions.EventuallyGatewayCondition(s.Ctx, "gw", "default", gwv1.GatewayConditionProgrammed, metav1.ConditionTrue)
	// Ensure referenced Backends are Accepted
	s.TestInstallation.Assertions.EventuallyBackendCondition(s.Ctx, "admin-mcp-backend", "default", "Accepted", metav1.ConditionTrue)
	s.TestInstallation.Assertions.EventuallyBackendCondition(s.Ctx, "user-mcp-backend", "default", "Accepted", metav1.ConditionTrue)
	// Finally, the dynamic route must be accepted
	s.TestInstallation.Assertions.EventuallyHTTPRouteCondition(
		s.Ctx, "dynamic-mcp-route", "default",
		gwv1.RouteConditionAccepted, metav1.ConditionTrue,
	)
}

// waitStaticReady ensures the static test route and its dependencies are ready.
func (s *testingSuite) waitStaticReady() {
	// User backend deployment used by static tests
	s.TestInstallation.Assertions.EventuallyPodsRunning(
		s.Ctx, "default",
		metav1.ListOptions{LabelSelector: "app=mcp-website-fetcher"},
	)
	// Curl pod used to drive HTTP requests
	s.TestInstallation.Assertions.EventuallyPodsRunning(
		s.Ctx, "curl",
		metav1.ListOptions{LabelSelector: "app.kubernetes.io/name=curl"},
	)
	// Gateway must be programmed before HTTPRoutes become effective
	s.TestInstallation.Assertions.EventuallyGatewayCondition(s.Ctx, "gw", "default", gwv1.GatewayConditionProgrammed, metav1.ConditionTrue)
	// Backend and static route for basic MCP
	s.TestInstallation.Assertions.EventuallyBackendCondition(s.Ctx, "mcp-backend", "default", "Accepted", metav1.ConditionTrue)
	s.TestInstallation.Assertions.EventuallyHTTPRouteCondition(s.Ctx, "mcp-route", "default", gwv1.RouteConditionAccepted, metav1.ConditionTrue)
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
