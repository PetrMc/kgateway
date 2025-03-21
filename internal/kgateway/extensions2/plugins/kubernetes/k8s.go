package kubernetes

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"knative.dev/pkg/network"

	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"istio.io/istio/pkg/kube/kclient"
	"istio.io/istio/pkg/kube/krt"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"

	"github.com/kgateway-dev/kgateway/v2/internal/kgateway/extensions2/common"
	extensionsplug "github.com/kgateway-dev/kgateway/v2/internal/kgateway/extensions2/plugin"
	"github.com/kgateway-dev/kgateway/v2/internal/kgateway/extensions2/settings"
	"github.com/kgateway-dev/kgateway/v2/internal/kgateway/ir"
	"github.com/kgateway-dev/kgateway/v2/internal/kgateway/krtcollections"
	"github.com/kgateway-dev/kgateway/v2/internal/kgateway/utils/krtutil"
)

const BackendClusterPrefix = "kube"

func NewPlugin(ctx context.Context, commoncol *common.CommonCollections) extensionsplug.Plugin {
	epSliceClient := kclient.New[*discoveryv1.EndpointSlice](commoncol.Client)
	endpointSlices := krt.WrapClient(epSliceClient, commoncol.KrtOpts.ToOptions("EndpointSlices")...)
	return NewPluginFromCollections(ctx, commoncol.KrtOpts, commoncol.Pods, commoncol.Services, endpointSlices, commoncol.Settings)
}

func NewPluginFromCollections(
	ctx context.Context,
	krtOpts krtutil.KrtOptions,
	pods krt.Collection[krtcollections.LocalityPod],
	services krt.Collection[*corev1.Service],
	endpointSlices krt.Collection[*discoveryv1.EndpointSlice],
	stngs settings.Settings,
) extensionsplug.Plugin {
	gk := schema.GroupKind{
		Group: corev1.GroupName,
		Kind:  "Service",
	}

	// TODO: reevaluate knative dep, dedupe with pkg/utils/kubeutils/dns.go
	clusterDomain := network.GetClusterDomainName()
	k8sServiceBackends := krt.NewManyCollection(services, func(kctx krt.HandlerContext, svc *corev1.Service) []ir.BackendObjectIR {
		uss := []ir.BackendObjectIR{}
		for _, port := range svc.Spec.Ports {
			uss = append(uss, ir.BackendObjectIR{
				ObjectSource: ir.ObjectSource{
					Kind:      gk.Kind,
					Group:     gk.Group,
					Namespace: svc.Namespace,
					Name:      svc.Name,
				},
				Obj: svc,
				// TODO: fill in ObjIR
				Port:              port.Port,
				AppProtocol:       translateAppProtocol(port.AppProtocol),
				GvPrefix:          BackendClusterPrefix,
				CanonicalHostname: fmt.Sprintf("%s.%s.svc.%s", svc.Name, svc.Namespace, clusterDomain),
			})
		}
		return uss
	}, krtOpts.ToOptions("KubernetesServiceBackends")...)

	inputs := krtcollections.NewGlooK8sEndpointInputs(stngs, krtOpts, endpointSlices, pods, k8sServiceBackends)
	k8sServiceEndpoints := krtcollections.NewGlooK8sEndpoints(ctx, inputs)

	return extensionsplug.Plugin{
		ContributesBackends: map[schema.GroupKind]extensionsplug.BackendPlugin{
			gk: {
				BackendInit: ir.BackendInit{
					InitBackend: processBackend,
				},
				Endpoints: k8sServiceEndpoints,
				Backends:  k8sServiceBackends,
			},
		},
	}
}

func translateAppProtocol(appProtocol *string) ir.AppProtocol {
	if appProtocol == nil {
		return ir.DefaultAppProtocol
	}
	switch *appProtocol {
	case "kubernetes.io/h2c":
		return ir.HTTP2AppProtocol
	default:
		return ir.DefaultAppProtocol
	}
}

func processBackend(ctx context.Context, in ir.BackendObjectIR, out *envoy_config_cluster_v3.Cluster) {
	out.ClusterDiscoveryType = &envoy_config_cluster_v3.Cluster_Type{
		Type: envoy_config_cluster_v3.Cluster_EDS,
	}
	out.EdsClusterConfig = &envoy_config_cluster_v3.Cluster_EdsClusterConfig{
		EdsConfig: &envoy_config_core_v3.ConfigSource{
			ResourceApiVersion: envoy_config_core_v3.ApiVersion_V3,
			ConfigSourceSpecifier: &envoy_config_core_v3.ConfigSource_Ads{
				Ads: &envoy_config_core_v3.AggregatedConfigSource{},
			},
		},
	}
}
