package mcp

import (
	"net/http"
	"path/filepath"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kgateway-dev/kgateway/v2/pkg/utils/fsutils"
	testmatchers "github.com/kgateway-dev/kgateway/v2/test/gomega/matchers"
	"github.com/kgateway-dev/kgateway/v2/test/kubernetes/e2e/defaults"
	"github.com/kgateway-dev/kgateway/v2/test/kubernetes/e2e/tests/base"
	. "github.com/onsi/gomega"
)

var (
	// manifests
	setupManifest        = filepath.Join(fsutils.MustGetThisDir(), "testdata", "common.yaml")
	staticSetupManifest  = filepath.Join(fsutils.MustGetThisDir(), "testdata", "static.yaml")
	dynamicSetupManifest = filepath.Join(fsutils.MustGetThisDir(), "testdata", "dynamic.yaml")
	adminSetupManifest   = filepath.Join(fsutils.MustGetThisDir(), "testdata", "admin.yaml")

	// Core infrastructure objects that we need to track
	gatewayObjectMeta = metav1.ObjectMeta{
		Name:      "gw",
		Namespace: "default",
	}
	gatewayService = &corev1.Service{ObjectMeta: gatewayObjectMeta}

	dynamicGatewayObjectMeta = metav1.ObjectMeta{
		Name:      "gw",
		Namespace: "default",
	}
	dynamicGatewayService = &corev1.Service{ObjectMeta: dynamicGatewayObjectMeta}

	expectStatus200Success = &testmatchers.HttpResponse{
		StatusCode: http.StatusOK,
		Body:       nil,
	}

	expectMCPSessionResponse = &testmatchers.HttpResponse{
		StatusCode: http.StatusOK,
		Body:       ContainSubstring("sessionId="),
	}

	expectMCPInitializeResponse = &testmatchers.HttpResponse{
		StatusCode: http.StatusOK,
		Body:       And(ContainSubstring("result"), ContainSubstring("protocolVersion")),
	}

	expectMCPResourcesResponse = &testmatchers.HttpResponse{
		StatusCode: http.StatusOK,
		Body:       And(ContainSubstring("result"), ContainSubstring("resources")),
	}

	expectMCPToolsResponse = &testmatchers.HttpResponse{
		StatusCode: http.StatusOK,
		Body:       And(ContainSubstring("result"), ContainSubstring("tools")),
	}

	// Base test setup - common resources + curl pod
	setup = base.TestCase{
		Manifests: []string{setupManifest, defaults.CurlPodManifest},
	}

	// Dynamic test setup (only dynamic-specific resources)
	dynamicSetup = base.TestCase{
		Manifests: []string{adminSetupManifest, dynamicSetupManifest},
	}

	// Static test setup (resources needed for non-dynamic tests)
	staticSetup = base.TestCase{
		Manifests: []string{staticSetupManifest},
	}
)
