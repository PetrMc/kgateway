package mcp

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/stretchr/testify/suite"

	"github.com/kgateway-dev/kgateway/v2/test/kubernetes/e2e"
	"github.com/kgateway-dev/kgateway/v2/test/kubernetes/e2e/tests/base"
)

var _ e2e.NewSuiteFunc = NewTestingSuite

type testingSuite struct {
	*base.BaseTestingSuite
	// mcpSessionID is the session ID for the MCP server
	mcpSessionID string
}

func NewTestingSuite(ctx context.Context, testInst *e2e.TestInstallation) suite.TestingSuite {
	return &testingSuite{
		BaseTestingSuite: base.NewBaseTestingSuite(ctx, testInst, setup, map[string]*base.TestCase{
			// Static tests
			"TestStaticReady": &staticSetup,
			"TestMCPWorkflow": &staticSetup,
			"TestSSEEndpoint": &staticSetup,
			// Dynamic tests
			"TestDynamicMCPConnection":       &dynamicSetup,
			"TestDynamicMCPAdminRouting":     &dynamicSetup,
			"TestDynamicMCPUserRouting":      &dynamicSetup,
			"TestDynamicMCPDefaultRouting":   &dynamicSetup,
			"TestDynamicMCPAdminVsUserTools": &dynamicSetup,
		}),
	}
}

func (s *testingSuite) TestMCPWorkflow() {
	// Single test that does the full workflow with session management
	s.T().Log("Testing complete MCP workflow with session management")

	// Ensure static components are ready
	s.waitStaticReady()

	// Step 1: Initialize and get session ID
	sessionID := s.initializeAndGetSessionID()
	s.Require().NotEmpty(sessionID, "Failed to get session ID from initialize")

	// Step 2: Test resources/list with session ID
	s.testResourcesListWithSession(sessionID)

	// Step 3: Test tools/list with session ID
	s.testToolsListWithSession(sessionID)
}

func (s *testingSuite) TestSSEEndpoint() {
	// Ensure static components are ready
	s.waitStaticReady()

	initBody := buildInitializeRequest("sse-client", 0)

	headers := mcpHeaders()
	out, err := s.execCurlMCP(8080, headers, initBody, "-N", "--max-time", "8")
	s.Require().NoError(err, "SSE initialize curl failed")

	s.requireHTTPStatus(out, 200)
	ctRe := regexp.MustCompile(`(?mi)^<\s*content-type:\s*text/event-stream\b`)
	if ctRe.FindStringIndex(out) == nil {
		s.T().Logf("missing text/event-stream content-type: %s", out)
		s.Require().Fail("expected Content-Type: text/event-stream in response headers")
	}

	payload, ok := FirstSSEDataPayload(out)
	s.Require().True(ok, "expected SSE data payload on initialize")
	s.Require().True(IsJSONValid(payload), "SSE payload must be valid JSON")

	// Validate initialize JSON payload
	var initResp InitializeResponse
	s.Require().NoError(json.Unmarshal([]byte(payload), &initResp), "unmarshal initialize payload")
	s.Require().Nil(initResp.Error, "initialize returned error: %+v", initResp.Error)
	s.Require().NotNil(initResp.Result, "initialize missing result")
	s.Require().Equal(mcpProto, initResp.Result.ProtocolVersion, "protocolVersion mismatch")
	sid := ExtractMCPSessionID(out)
	s.Require().NotEmpty(sid, "initialize must return mcp-session-id header")
}

func (s *testingSuite) TestDynamicMCPAdminRouting() {
	s.waitDynamicReady()
	s.T().Log("Testing dynamic MCP routing for admin user")

	mcpRequest := buildInitializeRequest("admin-client", 0)

	headers := withRouteHeaders(mcpHeaders(), map[string]string{"user-type": "admin"})
	outputStr, err := s.execCurlMCP(8080, headers, mcpRequest, "--max-time", "5")
	s.Require().NoError(err, "Failed to execute admin initialize request")
	s.requireHTTPStatus(outputStr, 200)
	s.T().Logf("admin initialize: %s", outputStr)

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
	s.Require().GreaterOrEqual(len(adminTools), 2, "admin should expose at least one tool")
	s.T().Logf("admin tools: %s", strings.Join(adminTools, ", "))
	s.T().Log("Admin routing working correctly")
}

func (s *testingSuite) TestDynamicMCPUserRouting() {
	s.waitDynamicReady()
	s.T().Log("Testing dynamic MCP routing for regular user")

	mcpRequest := buildInitializeRequest("user-client", 0)

	headers := withRouteHeaders(mcpHeaders(), map[string]string{"user-type": "user"})
	outputStr, err := s.execCurlMCP(8080, headers, mcpRequest, "--max-time", "5")
	s.Require().NoError(err, "Failed to execute user initialize request")
	s.requireHTTPStatus(outputStr, 200)
	s.T().Logf("user initialize: %s", outputStr)

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
	s.Require().Equal(len(userTools), 1, "user should expose at least one tool")
	s.T().Logf("user tools: %s", strings.Join(userTools, ", "))

	s.T().Log("User routing working correctly")
}

func (s *testingSuite) TestDynamicMCPDefaultRouting() {
	s.waitDynamicReady()
	s.T().Log("Testing dynamic MCP routing with no header (default to user)")

	// MCP initialize request with no user-type header
	mcpRequest := buildInitializeRequest("default-client", 0)

	headers := mcpHeaders()
	outputStr, err := s.execCurlMCP(8080, headers, mcpRequest, "--max-time", "5")
	s.Require().NoError(err, "Failed to execute default initialize request")
	s.requireHTTPStatus(outputStr, 200)
	s.T().Logf("default initialize: %s", outputStr)

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
	s.Require().Equal(len(defTools), 1, "default/user should expose at least one tool")
	s.T().Logf("default tools: %s", strings.Join(defTools, ", "))

	s.T().Log("Default routing working correctly")
}
