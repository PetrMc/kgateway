package registry

import (
	"context"
	"fmt"
	"maps"
	"os"
	"strings"

	"k8s.io/apimachinery/pkg/runtime/schema"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/kgateway-dev/kgateway/v2/internal/kgateway/extensions2/common"
	"github.com/kgateway-dev/kgateway/v2/internal/kgateway/extensions2/plugins/backend"
	"github.com/kgateway-dev/kgateway/v2/internal/kgateway/extensions2/plugins/backendtlspolicy"
	"github.com/kgateway-dev/kgateway/v2/internal/kgateway/extensions2/plugins/destrule"
	"github.com/kgateway-dev/kgateway/v2/internal/kgateway/extensions2/plugins/directresponse"
	"github.com/kgateway-dev/kgateway/v2/internal/kgateway/extensions2/plugins/httplistenerpolicy"
	"github.com/kgateway-dev/kgateway/v2/internal/kgateway/extensions2/plugins/istio"
	"github.com/kgateway-dev/kgateway/v2/internal/kgateway/extensions2/plugins/kubernetes"
	"github.com/kgateway-dev/kgateway/v2/internal/kgateway/extensions2/plugins/sandwich"
	"github.com/kgateway-dev/kgateway/v2/internal/kgateway/extensions2/plugins/serviceentry"
	"github.com/kgateway-dev/kgateway/v2/internal/kgateway/extensions2/plugins/trafficpolicy"
	"github.com/kgateway-dev/kgateway/v2/internal/kgateway/extensions2/plugins/waypoint"
	sdk "github.com/kgateway-dev/kgateway/v2/pkg/pluginsdk"
)

func mergedGw(funcs []sdk.GwTranslatorFactory) sdk.GwTranslatorFactory {
	return func(gw *gwv1.Gateway) sdk.KGwTranslator {
		for _, f := range funcs {
			ret := f(gw)
			if ret != nil {
				return ret
			}
		}
		return nil
	}
}

func mergeSynced(funcs []func() bool) func() bool {
	return func() bool {
		for _, f := range funcs {
			if !f() {
				return false
			}
		}
		return true
	}
}

func MergePlugins(plug ...sdk.Plugin) sdk.Plugin {
	ret := sdk.Plugin{
		ContributesPolicies:     make(map[schema.GroupKind]sdk.PolicyPlugin),
		ContributesBackends:     make(map[schema.GroupKind]sdk.BackendPlugin),
		ContributesRegistration: make(map[schema.GroupKind]func()),
	}
	var funcs []sdk.GwTranslatorFactory
	var hasSynced []func() bool
	for _, p := range plug {
		maps.Copy(ret.ContributesPolicies, p.ContributesPolicies)
		maps.Copy(ret.ContributesBackends, p.ContributesBackends)
		maps.Copy(ret.ContributesRegistration, p.ContributesRegistration)
		if p.ContributesGwTranslator != nil {
			funcs = append(funcs, p.ContributesGwTranslator)
		}
		if p.ExtraHasSynced != nil {
			hasSynced = append(hasSynced, p.ExtraHasSynced)
		}
	}
	ret.ContributesGwTranslator = mergedGw(funcs)
	ret.ExtraHasSynced = mergeSynced(hasSynced)
	return ret
}

// Plugins returns a list of enabled plugins, optionally filtered
func Plugins(ctx context.Context, commoncol *common.CommonCollections) []sdk.Plugin {
	excluded := map[string]bool{}
	fmt.Println("Excluding plugins using env var", os.Getenv("KGTW_EXCLUDE_PLUGINS"),)
	if excludedStr := os.Getenv("KGTW_EXCLUDE_PLUGINS"); excludedStr != "" {
		for _, name := range strings.Split(excludedStr, ",") {
			excluded[strings.TrimSpace(name)] = true
			fmt.Println("Excluding plugin", name)
		}
	}
	
	var plugins []sdk.Plugin
	add := func(name string, p sdk.Plugin) {
		if !excluded[name] {
			plugins = append(plugins, p)
		}
	}

	add("backend", backend.NewPlugin(ctx, commoncol))
	add("trafficpolicy", trafficpolicy.NewPlugin(ctx, commoncol))
	add("directresponse", directresponse.NewPlugin(ctx, commoncol))
	add("kubernetes", kubernetes.NewPlugin(ctx, commoncol))
	add("istio", istio.NewPlugin(ctx, commoncol))
	add("destrule", destrule.NewPlugin(ctx, commoncol))
	add("httplistenerpolicy", httplistenerpolicy.NewPlugin(ctx, commoncol))
	add("backendtlspolicy", backendtlspolicy.NewPlugin(ctx, commoncol))
	add("serviceentry", serviceentry.NewPlugin(ctx, commoncol))
	add("waypoint", waypoint.NewPlugin(ctx, commoncol))
	add("sandwich", sandwich.NewPlugin())

	return plugins
}
