package waypoint

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/onsi/gomega/gstruct"

	"github.com/kgateway-dev/kgateway/v2/pkg/utils/kubeutils/kubectl"
	"github.com/kgateway-dev/kgateway/v2/test/gomega/matchers"
)

var (
	hasHTTPRoute = matchers.HttpResponse{
		StatusCode: http.StatusOK,
		Headers: map[string]interface{}{
			"traversed-waypoint": "true",
		},
		Body: gstruct.Ignore(),
	}

	noHTTPRoute = matchers.HttpResponse{
		StatusCode: http.StatusOK,
		NotHeaders: []string{
			"traversed-waypoint",
		},
		Body: gstruct.Ignore(),
	}

	isOK = matchers.HttpResponse{
		StatusCode: http.StatusOK,
		Body:       gstruct.Ignore(),
	}

	// Response is forbidden
	isForbidden = matchers.HttpResponse{
		StatusCode: http.StatusForbidden,
		Body:       gstruct.Ignore(),
	}
)

func (s *testingSuite) TestServiceEntryHostnameHTTPRoute() {
	s.setNamespaceWaypointOrFail(testNamespace)
	s.applyOrFail("httproute-hostname.yaml", testNamespace)

	// svc-a has the parent ref, so only have the route there
	s.assertCurlHost(fromCurl, "se-a.serviceentry.com", hasHTTPRoute)
	s.assertCurlHost(fromCurl, "se-b.serviceentry.com", noHTTPRoute)
}

func (s *testingSuite) TestServiceEntryObjectHTTPRoute() {
	s.setNamespaceWaypointOrFail(testNamespace)
	s.applyOrFail("httproute-serviceentry.yaml", testNamespace)

	// svc-a has the parent ref, so only have the route there
	s.assertCurlHost(fromCurl, "se-a.serviceentry.com", hasHTTPRoute)
	s.assertCurlHost(fromCurl, "se-b.serviceentry.com", noHTTPRoute)
}

func (s *testingSuite) TestServiceHTTPRoute() {
	s.setNamespaceWaypointOrFail(testNamespace)
	s.applyOrFail("httproute-svc.yaml", testNamespace)

	// svc-a has the parent ref, so only have the route there
	s.assertCurlService(fromCurl, "svc-a", testNamespace, hasHTTPRoute)
	s.assertCurlService(fromCurl, "svc-b", testNamespace, noHTTPRoute)
}

func (s *testingSuite) TestGatewayHTTPRoute() {
	s.setNamespaceWaypointOrFail(testNamespace)
	s.applyOrFail("httproute-gw.yaml", testNamespace)

	// both get the route since we parent to the Gateway
	s.assertCurlService(fromCurl, "svc-a", testNamespace, hasHTTPRoute)
	s.assertCurlService(fromCurl, "svc-b", testNamespace, hasHTTPRoute)
}

func (s *testingSuite) TestAuthorizationPolicies() {
	s.T().Run("ComplexRules", func(t *testing.T) {
		s.runAuthzComplexRule(t)
	})
	s.T().Run("GatewayAttached", func(t *testing.T) {
		s.runAuthzGatewayAttached()
	})
	s.T().Run("NamespaceWide", func(t *testing.T) {
		s.runAuthzNamespaceWide()
	})
	s.T().Run("MultiService", func(t *testing.T) {
		s.runAuthzMultiService()
	})
}

func (s *testingSuite) runAuthzGatewayAttached() {
	s.setNamespaceWaypointOrFail(testNamespace)
	s.applyOrFail("authz-l7.yaml", testNamespace)

	// ensure waypoint attachment, and all requests fromCurl succeed
	s.assertCurlService(fromCurl, "svc-a", testNamespace, hasEnvoy)
	s.assertCurlService(fromCurl, "svc-b", testNamespace, hasEnvoy)

	// ensure authz is only applied to svc-a
	s.assertCurlService(fromNotCurl, "svc-a", testNamespace, hasEnvoy)
	s.assertCurlService(fromNotCurl, "svc-b", testNamespace, isForbidden)
}

func (s *testingSuite) runAuthzNamespaceWide() {
	s.setNamespaceWaypointOrFail(testNamespace)
	s.applyOrFail("authz-gateway-ref.yaml", testNamespace)

	// Verify waypoint attachment
	s.assertCurlService(fromCurl, "svc-a", testNamespace, isForbidden)
	s.assertCurlService(fromCurl, "svc-b", testNamespace, isForbidden)

	// Verify that policy applies to all services for notcurl
	s.assertCurlService(fromNotCurl, "svc-a", testNamespace, isForbidden)
	s.assertCurlService(fromNotCurl, "svc-b", testNamespace, isForbidden)

	// repeat with POST (should be allowed)
	s.assertCurlServicePost(fromCurl, "svc-a", testNamespace, hasEnvoy)
	s.assertCurlServicePost(fromCurl, "svc-b", testNamespace, hasEnvoy)
	s.assertCurlServicePost(fromNotCurl, "svc-a", testNamespace, hasEnvoy)
	s.assertCurlServicePost(fromNotCurl, "svc-b", testNamespace, hasEnvoy)
}

func (s *testingSuite) runAuthzMultiService() {
	s.setNamespaceWaypointOrFail(testNamespace)
	s.applyOrFail("authz-multi-service.yaml", testNamespace)

	// Verify waypoint attachment
	s.assertCurlService(fromCurl, "svc-a", testNamespace, isForbidden)
	s.assertCurlService(fromCurl, "svc-b", testNamespace, isForbidden)

	// Verify that policy applies to all services for notcurl
	s.assertCurlService(fromNotCurl, "svc-a", testNamespace, isForbidden)
	s.assertCurlService(fromNotCurl, "svc-b", testNamespace, isForbidden)

	// repeat with POST (should be allowed)
	s.assertCurlServicePost(fromCurl, "svc-a", testNamespace, hasEnvoy)
	s.assertCurlServicePost(fromCurl, "svc-b", testNamespace, hasEnvoy)
	s.assertCurlServicePost(fromNotCurl, "svc-a", testNamespace, hasEnvoy)
	s.assertCurlServicePost(fromNotCurl, "svc-b", testNamespace, hasEnvoy)
}

func (s *testingSuite) runAuthzComplexRule(t *testing.T) {
	s.setNamespaceWaypointOrFail(testNamespace)
	s.applyOrFail("authz-complex-rules.yaml", testNamespace)

	type fromSpec struct {
		name string
		opts kubectl.PodExecOptions
	}
	froms := []fromSpec{
		{"curl", fromCurl},
		{"notcurl", fromNotCurl},
	}
	services := []string{"svc-a", "svc-b"}
	methods := []string{"GET", "POST"}
	paths := []string{"", "/admin/"}

	// Only these combinations are denied
	denyMap := map[string]struct{}{
		"notcurl|svc-a|GET|/admin/":  {},
		"notcurl|svc-a|POST|/admin/": {},
	}

	for _, from := range froms {
		for _, svc := range services {
			for _, method := range methods {
				for _, path := range paths {
					key := fmt.Sprintf("%s|%s|%s|%s", from.name, svc, method, path)
					expected := hasEnvoy
					if _, deny := denyMap[key]; deny {
						expected = isForbidden
					}

					t.Run(key, func(t *testing.T) {
						s.assertCurlGeneric(from.opts, svc, method, path, expected)
					})
				}
			}
		}
	}
}
