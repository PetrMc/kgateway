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

func (k GatewayTargetKey) String() string {
	return fmt.Sprintf("%s/%s/%s/%s", k.Group, k.Kind, k.Namespace, k.Name)
}

// GetAuthorizationPoliciesForGateway returns policies targeting a specific gateway
func (w *waypointQueries) GetAuthorizationPoliciesForGateway(
	kctx krt.HandlerContext,
	ctx context.Context,
	gateway *gwapi.Gateway,
	rootNamespace string) []*authcr.AuthorizationPolicy {

	// Get policies targeting this gateway directly using the index
	gwKey := GatewayTargetKey{
		Name:      gateway.GetName(),
		Namespace: gateway.GetNamespace(),
		Group:     "gateway.networking.k8s.io",
		Kind:      "Gateway",
	}
	fmt.Printf("Looking up Gateway policies with key: %+v in the list of %d policies\n", gwKey, len(w.authzPolicies.List()))

	// Get all indexed policies targeting this gateway
	allPolicies := krt.Fetch(kctx, w.authzPolicies, krt.FilterIndex(w.byGatewayTarget, gwKey))
	// Add root namespace policies if needed
	if rootNamespace != "" && rootNamespace != gateway.GetNamespace() {
		gwClassKey := GatewayTargetKey{
			Name:      "kgateway-waypoint",
			Namespace: rootNamespace,
			Group:     "gateway.networking.k8s.io",
			Kind:      "GatewayClass",
		}
		rootPolicies := krt.Fetch(kctx, w.authzPolicies, krt.FilterIndex(w.byGatewayTarget, gwClassKey))
		allPolicies = append(allPolicies, rootPolicies...)
	}
	fmt.Printf("Found %d policies for Gateway with key %s\n", len(allPolicies), gwKey)
	for i, p := range allPolicies {
		fmt.Printf("  Policy %d: %s/%s (deletion: %v)\n", i,
			p.GetNamespace(), p.GetName(), p.GetDeletionTimestamp() != nil)
	}

	// Let the existing matcher & RBAC builder handle filtering
	// Don't attempt to reimplement the filtering logic here
	return allPolicies
}

// GetAuthorizationPoliciesForService returns policies targeting a specific service
func (w *waypointQueries) GetAuthorizationPoliciesForService(
	kctx krt.HandlerContext,
	ctx context.Context,
	svc *Service) []*authcr.AuthorizationPolicy {

	providerID := svc.Provider()

	svcKey := ServiceTargetKey{
		Name:      svc.GetName(),
		Namespace: svc.GetNamespace(),
		Provider:  providerID,
	}

	svcPolicies := krt.Fetch(kctx, w.authzPolicies, krt.FilterIndex(w.byServiceTarget, svcKey))
	fmt.Printf("Looking up Service policies with key: %+v in the list of %d policies\n", svcKey, len(w.authzPolicies.List()))
	fmt.Printf("Found %d policies for service %s/%s for the key: %s\n",
		len(svcPolicies), svc.GetNamespace(), svc.GetName(), svcKey)	
	return svcPolicies
}
