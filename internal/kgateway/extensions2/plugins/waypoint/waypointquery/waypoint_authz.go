package waypointquery

import (
	"context"
	"fmt"

	authcr "istio.io/client-go/pkg/apis/security/v1"
	"istio.io/istio/pilot/pkg/serviceregistry/provider"
	"istio.io/istio/pkg/kube/krt"
	gwapi "sigs.k8s.io/gateway-api/apis/v1"
)

// ServiceTargetKey identifies a service that policies can target
type ServiceTargetKey struct {
	Name      string
	Namespace string
	Provider  provider.ID
}

func (k GatewayTargetKey) String() string {
	return fmt.Sprintf("%s/%s/%s/%s", k.Group, k.Kind, k.Namespace, k.Name)
}

// GatewayTargetKey identifies a gateway that policies can target
type GatewayTargetKey struct {
	Name      string
	Namespace string
	Group     string
	Kind      string
}

func (k ServiceTargetKey) String() string {
	return fmt.Sprintf("%s/%s/%v", k.Namespace, k.Name, k.Provider)
}

// GetAuthorizationPoliciesForGateway returns policies targeting a specific gateway
func (w *waypointQueries) GetAuthorizationPoliciesForGateway(
	kctx krt.HandlerContext,
	ctx context.Context,
	gateway *gwapi.Gateway,
	rootNamespace string) []*authcr.AuthorizationPolicy {

	// Get policies targeting this gateway directly using the index
	key := GatewayTargetKey{
		Name:      gateway.GetName(),
		Namespace: gateway.GetNamespace(),
		Group:     "gateway.networking.k8s.io",
		Kind:      "Gateway",
	}

	// Get all indexed policies targeting this gateway
	gatewayPolicies := krt.Fetch(kctx, w.authzPolicies, krt.FilterIndex(w.byGatewayTarget, key))

	// Get all policies from namespace and root namespace (same as existing method)
	namespacePolicies := krt.Fetch(kctx, w.authzPolicies, krt.FilterIndex(w.byNamespace, gateway.GetNamespace()))

	allPolicies := append(gatewayPolicies, namespacePolicies...)

	// Add root namespace policies if needed
	if rootNamespace != "" && rootNamespace != gateway.GetNamespace() {
		rootPolicies := krt.Fetch(kctx, w.authzPolicies, krt.FilterIndex(w.byNamespace, rootNamespace))
		allPolicies = append(allPolicies, rootPolicies...)
	}

	// Let the existing matcher & RBAC builder handle filtering
	// Don't attempt to reimplement the filtering logic here
	return allPolicies
}
