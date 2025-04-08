package waypointquery

import (
	"context"

	"istio.io/istio/pilot/pkg/serviceregistry/provider"
	"istio.io/istio/pkg/kube/krt"
	gwapi "sigs.k8s.io/gateway-api/apis/v1"
	authcr "istio.io/client-go/pkg/apis/security/v1"
)

// ServiceTargetKey identifies a service that policies can target
type ServiceTargetKey struct {
	Name      string
	Namespace string
	Provider  provider.ID
}

// GatewayTargetKey identifies a gateway that policies can target
type GatewayTargetKey struct {
	Name      string
	Namespace string
	Group     string
	Kind      string
}

// GetAuthorizationPoliciesForService returns policies targeting a specific service
func (w *waypointQueries) GetAuthorizationPoliciesForService(
	kctx krt.HandlerContext,
	ctx context.Context,
	service *Service,
	rootNamespace string) []*authcr.AuthorizationPolicy {

	// Get policies directly targeting this service
	key := ServiceTargetKey{
		Name:      service.GetName(),
		Namespace: service.GetNamespace(),
		Provider:  service.Provider(),
	}

	directPolicies := krt.Fetch(kctx, w.authzPolicies, krt.FilterIndex(w.byServiceTarget, key))

	// Get namespace-wide policies (no targetRefs)
	var namespacePolicies []*authcr.AuthorizationPolicy
	allNamespacePolicies := krt.Fetch(kctx, w.authzPolicies, krt.FilterIndex(w.byNamespace, service.GetNamespace()))
	for _, p := range allNamespacePolicies {
		if len(p.Spec.GetTargetRefs()) == 0 {
			namespacePolicies = append(namespacePolicies, p)
		}
	}

	// Combine results
	policies := append(directPolicies, namespacePolicies...)

	// Add relevant root namespace policies
	if rootNamespace != "" && rootNamespace != service.GetNamespace() {
		// Get policies from root namespace that target this service
		// Reuse the same key since we're targeting the same service
		rootPolicies := krt.Fetch(kctx, w.authzPolicies, krt.FilterIndex(w.byServiceTarget, key))
		policies = append(policies, rootPolicies...)
	}

	return policies
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

func (w *waypointQueries) GetAuthorizationPolicies(kctx krt.HandlerContext, ctx context.Context, targetNamespace, rootNamespace string) []*authcr.AuthorizationPolicy {
	// Get all policies in the target namespace
	policies := krt.Fetch(kctx, w.authzPolicies, krt.FilterIndex(w.byNamespace, targetNamespace))

	// Get all policies in the root namespace
	if rootNamespace != "" && rootNamespace != targetNamespace {
		rootPolicies := krt.Fetch(kctx, w.authzPolicies, krt.FilterIndex(w.byNamespace, rootNamespace))
		policies = append(policies, rootPolicies...)
	}

	// Filter policies to only include those targeting services in the target namespace
	filteredPolicies := make([]*authcr.AuthorizationPolicy, 0, len(policies))
	for _, policy := range policies {
		for _, targetRef := range policy.Spec.GetTargetRefs() {
			if targetRef.GetKind() == "Service" && targetRef.GetGroup() == "" {
				// If the policy targets a service in the target namespace, include it
				targetNamespaceMatches := targetRef.GetNamespace() == "" || targetRef.GetNamespace() == targetNamespace
				if targetNamespaceMatches {
					filteredPolicies = append(filteredPolicies, policy)
					break
				}
			}
		}
	}
	return filteredPolicies
}
