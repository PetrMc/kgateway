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
	setupManifest = filepath.Join(fsutils.MustGetThisDir(), "testdata", "setup.yaml")

	// Core infrastructure objects that we need to track
	gatewayObjectMeta = metav1.ObjectMeta{
		Name:      "gw",
		Namespace: "default",
	}
	gatewayService = &corev1.Service{ObjectMeta: gatewayObjectMeta}

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
		Body:       ContainSubstring("result"),
	}

	// Base test setup - common infrastructure for all tests
	setup = base.TestCase{
		Manifests: []string{setupManifest, defaults.CurlPodManifest},
	}
)
