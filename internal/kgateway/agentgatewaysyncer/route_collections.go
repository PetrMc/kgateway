package agentgatewaysyncer

import (
	"fmt"
	"iter"
	"strings"

	"github.com/agentgateway/agentgateway/go/api"
	networkingclient "istio.io/client-go/pkg/apis/networking/v1"
	"istio.io/istio/pkg/config"
	"istio.io/istio/pkg/kube/controllers"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/slices"
	"istio.io/istio/pkg/util/protomarshal"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	inf "sigs.k8s.io/gateway-api-inference-extension/api/v1alpha2"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"
	gwv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"

	"github.com/kgateway-dev/kgateway/v2/api/v1alpha1"
	"github.com/kgateway-dev/kgateway/v2/internal/kgateway/krtcollections"
	krtinternal "github.com/kgateway-dev/kgateway/v2/internal/kgateway/utils/krtutil"
	"github.com/kgateway-dev/kgateway/v2/internal/kgateway/wellknown"
	agwir "github.com/kgateway-dev/kgateway/v2/pkg/agentgateway/ir"
	"github.com/kgateway-dev/kgateway/v2/pkg/pluginsdk"
	pluginsdkir "github.com/kgateway-dev/kgateway/v2/pkg/pluginsdk/ir"
	"github.com/kgateway-dev/kgateway/v2/pkg/pluginsdk/reporter"
	"github.com/kgateway-dev/kgateway/v2/pkg/reports"
)

// ADPRouteCollection creates the collection of translated routes
func ADPRouteCollection(
	httpRouteCol krt.Collection[*gwv1.HTTPRoute],
	grpcRouteCol krt.Collection[*gwv1.GRPCRoute],
	tcpRouteCol krt.Collection[*gwv1alpha2.TCPRoute],
	tlsRouteCol krt.Collection[*gwv1alpha2.TLSRoute],
	inputs RouteContextInputs,
	krtopts krtinternal.KrtOptions,
	plugins pluginsdk.Plugin,
) krt.Collection[ADPResourcesForGateway] {
	// TODO(npolshak): look into using RouteIndex instead of raw collections to support targetRefs: https://github.com/kgateway-dev/kgateway/issues/11838
	httpRoutes := createRouteCollection(httpRouteCol, inputs, krtopts, plugins, "ADPHTTPRoutes",
		func(ctx RouteContext, obj *gwv1.HTTPRoute, rep reporter.Reporter) (RouteContext, iter.Seq2[ADPRoute, *reporter.RouteCondition]) {
			// HTTP-specific preprocessing: attach policies and setup plugins
			attachRoutePolicies(&ctx, obj)
			ctx.pluginPasses = newAgentGatewayPasses(plugins, rep, ctx.AttachedPolicies)

			route := obj.Spec
			return ctx, func(yield func(ADPRoute, *reporter.RouteCondition) bool) {
				for n, r := range route.Rules {
					// split the rule to make sure each rule has up to one match
					matches := slices.Reference(r.Matches)
					if len(matches) == 0 {
						matches = append(matches, nil)
					}
					for idx, m := range matches {
						if m != nil {
							r.Matches = []gwv1.HTTPRouteMatch{*m}
						}
						res, err := convertHTTPRouteToADP(ctx, r, obj, n, idx)
						if !yield(ADPRoute{Route: res}, err) {
							return
						}
					}
				}
			}
		})

	grpcRoutes := createRouteCollection(grpcRouteCol, inputs, krtopts, plugins, "ADPGRPCRoutes",
		func(ctx RouteContext, obj *gwv1.GRPCRoute, rep reporter.Reporter) (RouteContext, iter.Seq2[ADPRoute, *reporter.RouteCondition]) {
			route := obj.Spec
			return ctx, func(yield func(ADPRoute, *reporter.RouteCondition) bool) {
				for n, r := range route.Rules {
					// Convert the entire rule with all matches at once
					res, err := convertGRPCRouteToADP(ctx, r, obj, n)
					if !yield(ADPRoute{Route: res}, err) {
						return
					}
				}
			}
		})

	tcpRoutes := createTCPRouteCollection(tcpRouteCol, inputs, krtopts, plugins, "ADPTCPRoutes",
		func(ctx RouteContext, obj *gwv1alpha2.TCPRoute, rep reporter.Reporter) (RouteContext, iter.Seq2[ADPTCPRoute, *reporter.RouteCondition]) {
			route := obj.Spec
			return ctx, func(yield func(ADPTCPRoute, *reporter.RouteCondition) bool) {
				for n, r := range route.Rules {
					// Convert the entire rule with all matches at once
					res, err := convertTCPRouteToADP(ctx, r, obj, n)
					if !yield(ADPTCPRoute{TCPRoute: res}, err) {
						return
					}
				}
			}
		})

	tlsRoutes := createTCPRouteCollection(tlsRouteCol, inputs, krtopts, plugins, "ADPTLSRoutes",
		func(ctx RouteContext, obj *gwv1alpha2.TLSRoute, rep reporter.Reporter) (RouteContext, iter.Seq2[ADPTCPRoute, *reporter.RouteCondition]) {
			route := obj.Spec
			return ctx, func(yield func(ADPTCPRoute, *reporter.RouteCondition) bool) {
				for n, r := range route.Rules {
					// Convert the entire rule with all matches at once
					res, err := convertTLSRouteToADP(ctx, r, obj, n)
					if !yield(ADPTCPRoute{TCPRoute: res}, err) {
						return
					}
				}
			}
		})

	routes := krt.JoinCollection([]krt.Collection[ADPResourcesForGateway]{httpRoutes, grpcRoutes, tcpRoutes, tlsRoutes}, krtopts.ToOptions("ADPRoutes")...)

	return routes
}

// buildAttachedRoutesMap builds a map of gateway -> section name -> route count,
func buildAttachedRoutesMap(
	parentRefs []routeParentReference,
	routeNN types.NamespacedName,
) map[types.NamespacedName]map[string]uint {

	attached := make(map[types.NamespacedName]map[string]uint)

	// robust dedupe key
	type attachKey struct {
		gw       types.NamespacedName
		listener string
		route    types.NamespacedName
	}
	seen := make(map[attachKey]struct{})

	// NOTE: This helper counts every (gw, listener) in parentRefs.
	// Prefer buildAttachedRoutesMapAllowed() for "only-allowed" counting.
	for i, parent := range parentRefs {
		if parent.ParentKey.Kind != wellknown.GatewayGVK {
			continue
		}
		gw := types.NamespacedName{Namespace: parent.ParentKey.Namespace, Name: parent.ParentKey.Name}
		lis := string(parent.ParentSection)

		// high-signal debug
		fmt.Printf("ATTACH-COUNT: route=%s gw=%s listener=%q (idx=%d)\n",
			routeNN.String(), gw.String(), lis, i)

		k := attachKey{gw: gw, listener: lis, route: routeNN}
		if _, ok := seen[k]; ok {
			// duplicate for same (gw,listener,route) => ignore
			continue
		}
		seen[k] = struct{}{}

		if attached[gw] == nil {
			attached[gw] = make(map[string]uint)
		}
		attached[gw][lis]++
	}

	// summary debug
	fmt.Printf("ATTACH-COUNT-SUMMARY: route=%s -> %d gateways\n", routeNN.String(), len(attached))
	for gw, m := range attached {
		for lis, c := range m {
			fmt.Printf("  gw=%s listener=%q count+=%d\n", gw.String(), lis, c)
		}
	}
	return attached
}

// processParentReferences processes filtered parent references and builds resources per gateway.
// It emits exactly one ParentStatus per Gateway (aggregate across listeners).
// If no listeners are allowed, the Accepted reason is:
//   - NotAllowedByListeners  => when the parent Gateway is cross-namespace w.r.t. the route
//   - NoMatchingListenerHostname => otherwise
func processParentReferences[T any](
	parentRefs []routeParentReference,
	gwResult conversionResult[T],
	routeNN types.NamespacedName, // <-- route namespace/name so we can detect cross-NS parents
	routeReporter reporter.RouteReporter,
	resourceMapper func(T, routeParentReference) *api.Resource,
) map[types.NamespacedName][]*api.Resource {
	resourcesPerGateway := make(map[types.NamespacedName][]*api.Resource)

	fmt.Printf("DEBUG: processParentReferences: route=%s parents=%d\n", routeNN.String(), len(parentRefs))

	// Build the "allowed" set from filteredReferences (listener-scoped).
	allowed := make(map[string]struct{})
	for _, p := range filteredReferences(parentRefs) {
		if p.ParentKey.Kind != wellknown.GatewayGVK {
			continue
		}
		k := fmt.Sprintf("%s/%s/%s/%s", p.ParentKey.Namespace, p.ParentKey.Name, p.ParentKey.Kind, string(p.ParentSection))
		allowed[k] = struct{}{}
	}

	// Aggregate per Gateway for status; also track whether any raw parent was cross-namespace.
	type gwAgg struct {
		anyAllowed bool
		rep        routeParentReference
	}
	agg := make(map[types.NamespacedName]*gwAgg)
	crossNS := make(map[types.NamespacedName]bool)

	for _, p := range parentRefs {
		if p.ParentKey.Kind != wellknown.GatewayGVK {
			continue
		}
		gwNN := types.NamespacedName{Namespace: p.ParentKey.Namespace, Name: p.ParentKey.Name}
		if _, ok := agg[gwNN]; !ok {
			agg[gwNN] = &gwAgg{anyAllowed: false, rep: p}
		}
		if p.ParentKey.Namespace != routeNN.Namespace {
			crossNS[gwNN] = true
		}
	}

	// If conversion (backend/filter resolution) failed, ResolvedRefs=False for all parents.
	resolvedOK := (gwResult.error == nil)

	// Consider each raw parentRef (listener-scoped) for mapping.
	idx := 0
	for _, parent := range parentRefs {
		idx++

		if parent.ParentKey.Kind != wellknown.GatewayGVK {
			fmt.Printf("DEBUG: [%d] SKIP non-Gateway kind=%q route=%s parent=%s/%s listener=%q\n",
				idx, parent.ParentKey.Kind, routeNN.String(), parent.ParentKey.Namespace, parent.ParentKey.Name, string(parent.ParentSection))
			continue
		}

		gwNN := types.NamespacedName{Namespace: parent.ParentKey.Namespace, Name: parent.ParentKey.Name}
		listener := string(parent.ParentSection)
		keyStr := fmt.Sprintf("%s/%s/%s/%s", parent.ParentKey.Namespace, parent.ParentKey.Name, parent.ParentKey.Kind, listener)
		_, isAllowed := allowed[keyStr]

		fmt.Printf("DEBUG: [%d] CONSIDER route=%s gw=%s listener=%q allowed=%v\n",
			idx, routeNN.String(), gwNN.String(), listener, isAllowed)

		if isAllowed {
			if a := agg[gwNN]; a != nil {
				a.anyAllowed = true
			}
		}

		// Only attach resources when listener is allowed. Even if ResolvedRefs is false,
		// we still attach so any DirectResponse policy can return 5xx as required.
		if !isAllowed {
			continue
		}

		var mapped []*api.Resource
		routes := gwResult.routes
		mapped = make([]*api.Resource, 0, len(routes))
		for i := range routes {
			if r := resourceMapper(routes[i], parent); r != nil {
				mapped = append(mapped, r)
			}
		}

		fmt.Printf("DEBUG: STORING route report for %s with parent %s\n", routeNN.String(), gwNN.String())
		fmt.Printf("DEBUG: [%d] ACCEPT route=%s gw=%s listener=%q resources=%d\n",
			idx, routeNN.String(), gwNN.String(), listener, len(mapped))

		resourcesPerGateway[gwNN] = append(resourcesPerGateway[gwNN], mapped...)
	}

	// Emit exactly ONE ParentStatus per Gateway (aggregate across listeners; no SectionName).
	for gwNN, a := range agg {
		parent := a.rep
		prStatusRef := parent.OriginalReference
		{
			g := gwv1.Group(wellknown.GatewayGVK.Group)
			k := gwv1.Kind(wellknown.GatewayGVK.Kind)
			ns := gwv1.Namespace(parent.ParentKey.Namespace)
			prStatusRef.Group = &g
			prStatusRef.Kind = &k
			prStatusRef.Namespace = &ns
			prStatusRef.Name = gwv1.ObjectName(parent.ParentKey.Name)
			prStatusRef.SectionName = nil
		}
		pr := routeReporter.ParentRef(&prStatusRef)
		resolvedReason := reasonResolvedRefs(gwResult.error, resolvedOK)

		if a.anyAllowed {
			pr.SetCondition(reporter.RouteCondition{
				Type:   gwv1.RouteConditionAccepted,
				Status: metav1.ConditionTrue,
				Reason: gwv1.RouteReasonAccepted,
			})
		} else {
			// Nothing attached: choose reason based on *why* it wasn't allowed.
			// Priority:
			// 1) Cross-namespace and listeners don’t allow it -> NotAllowedByListeners
			// 2) sectionName specified but no such listener on the parent -> NoMatchingParent
			// 3) Otherwise, no hostname intersection -> NoMatchingListenerHostname
			reason := gwv1.RouteConditionReason("NoMatchingListenerHostname")
			msg := "No route hostnames intersect any listener hostname"
			if crossNS[gwNN] {
				reason = gwv1.RouteReasonNotAllowedByListeners
				msg = "Parent listener not usable or not permitted"
			} else if a.rep.OriginalReference.SectionName != nil {
				// Use string literal to avoid compile issues if the constant name differs.
				reason = gwv1.RouteConditionReason("NoMatchingParent")
				msg = "No listener with the specified sectionName on the parent Gateway"
			}
			pr.SetCondition(reporter.RouteCondition{
				Type:    gwv1.RouteConditionAccepted,
				Status:  metav1.ConditionFalse,
				Reason:  reason,
				Message: msg,
			})
		}

		pr.SetCondition(reporter.RouteCondition{
			Type: gwv1.RouteConditionResolvedRefs,
			Status: func() metav1.ConditionStatus {
				if resolvedOK {
					return metav1.ConditionTrue
				}
				return metav1.ConditionFalse
			}(),
			Reason: resolvedReason,
		})

		fmt.Printf("DEBUG: EMIT ParentStatus gw=%s Accepted=%v ResolvedRefs=%v crossNS=%v\n",
			gwNN.String(), a.anyAllowed, resolvedOK, crossNS[gwNN])
	}

	fmt.Printf("DEBUG: processParentReferences DONE route=%s gateways=%d\n", routeNN.String(), len(resourcesPerGateway))
	for gw, rs := range resourcesPerGateway {
		fmt.Printf("DEBUG:   gw=%s total_resources=%d\n", gw.String(), len(rs))
	}
	return resourcesPerGateway
}

// reasonResolvedRefs picks a ResolvedRefs reason from a conversion failure condition.
// Falls back to "ResolvedRefs" (when ok) or "Invalid" (when not ok and no specific reason).
func reasonResolvedRefs(cond *reporter.RouteCondition, ok bool) gwv1.RouteConditionReason {
	if ok {
		return gwv1.RouteReasonResolvedRefs
	}
	if cond != nil && cond.Reason != "" {
		return cond.Reason
	}
	return gwv1.RouteConditionReason("Invalid")
}

// buildAttachedRoutesMapAllowed is the same as buildAttachedRoutesMap,
// but only for already-evaluated, allowed parentRefs.
func buildAttachedRoutesMapAllowed(
	allowedParents []routeParentReference,
	routeNN types.NamespacedName,
) map[types.NamespacedName]map[string]uint {
	attached := make(map[types.NamespacedName]map[string]uint)
	type attachKey struct {
		gw       types.NamespacedName
		listener string
		route    types.NamespacedName
	}
	seen := make(map[attachKey]struct{})

	for i, parent := range allowedParents {
		if parent.ParentKey.Kind != wellknown.GatewayGVK {
			continue
		}
		gw := types.NamespacedName{Namespace: parent.ParentKey.Namespace, Name: parent.ParentKey.Name}
		lis := string(parent.ParentSection)

		fmt.Printf("ATTACH-COUNT: route=%s gw=%s listener=%q (idx=%d)\n",
			routeNN.String(), gw.String(), lis, i)

		k := attachKey{gw: gw, listener: lis, route: routeNN}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}

		if attached[gw] == nil {
			attached[gw] = make(map[string]uint)
		}
		attached[gw][lis]++
	}

	fmt.Printf("ATTACH-COUNT-SUMMARY: route=%s -> %d gateways\n", routeNN.String(), len(attached))
	for gw, m := range attached {
		for lis, c := range m {
			fmt.Printf("  gw=%s listener=%q count+=%d\n", gw.String(), lis, c)
		}
	}
	return attached
}

// createRouteCollection is a generic helper function that creates a KRT collection for any route type
// by extracting the common logic shared between HTTP and GRPC route collections
func createRouteCollection[T controllers.Object](
	routeCol krt.Collection[T],
	inputs RouteContextInputs,
	krtopts krtinternal.KrtOptions,
	plugins pluginsdk.Plugin,
	collectionName string,
	translator func(ctx RouteContext, obj T, rep reporter.Reporter) (RouteContext, iter.Seq2[ADPRoute, *reporter.RouteCondition]),
) krt.Collection[ADPResourcesForGateway] {
	return krt.NewManyCollection(routeCol, func(krtctx krt.HandlerContext, obj T) []ADPResourcesForGateway {
		logger.Debug("translating route", "route_name", obj.GetName(), "resource_version", obj.GetResourceVersion())

		ctx := inputs.WithCtx(krtctx)
		rm := reports.NewReportMap()
		rep := reports.NewReporter(&rm)
		routeReporter := rep.Route(obj)

		// Apply route-specific preprocessing and get the translator
		ctx, translatorSeq := translator(ctx, obj, rep)

		parentRefs, gwResult := computeRoute(ctx, obj, func(obj T) iter.Seq2[ADPRoute, *reporter.RouteCondition] {
			return translatorSeq
		})
		fmt.Printf("DEBUG: route %s/%s parents=%d\n", obj.GetNamespace(), obj.GetName(), len(parentRefs))

		for i, p := range parentRefs {
			fmt.Printf("DEBUG:   [%d] gw=%s/%s section=%q internalName=%q\n",
				i,
				p.ParentKey.Namespace, p.ParentKey.Name,
				string(p.ParentSection), p.InternalName)
		}

		// gateway -> section name -> route count
		routeNN := types.NamespacedName{Namespace: obj.GetNamespace(), Name: obj.GetName()}
		allParentGWs := make(map[types.NamespacedName]struct{})
		for _, p := range parentRefs {
			if p.ParentKey.Kind != wellknown.GatewayGVK {
				continue
			}
			gw := types.NamespacedName{Namespace: p.ParentKey.Namespace, Name: p.ParentKey.Name}
			allParentGWs[gw] = struct{}{}
		}
		ln := listenersPerGateway(parentRefs)
		allowedParents := filteredReferences(parentRefs)
		attachedRoutes := buildAttachedRoutesMapAllowed(allowedParents, routeNN)
		ensureZeroes(attachedRoutes, ln)
		resourcesPerGateway := processParentReferences(
			parentRefs,
			gwResult,
			types.NamespacedName{Namespace: obj.GetNamespace(), Name: obj.GetName()}, // was obj.GetName()
			routeReporter,
			func(e ADPRoute, parent routeParentReference) *api.Resource {
				inner := protomarshal.Clone(e.Route)

				// Keep binding via internal listener name
				_, name, _ := strings.Cut(parent.InternalName, "/")
				inner.ListenerKey = name

				// Only suffix with sectionName when it exists
				if sec := string(parent.ParentSection); sec != "" {
					inner.Key = inner.GetKey() + "." + sec
				} else {
					inner.Key = inner.GetKey()
				}

				return toADPResource(ADPRoute{Route: inner})
			},
		)

		var results []ADPResourcesForGateway
		seen := make(map[types.NamespacedName]struct{})
		// First: gateways that produced resources.
		for gw, res := range resourcesPerGateway {
			var ar map[string]uint
			if attachedRoutes[gw] != nil {
				ar = attachedRoutes[gw]
			}
			results = append(results, toResourceWithRoutes(gw, res, ar, rm))
			seen[gw] = struct{}{}
		}
		// Second: gateways that had parentRefs (so attachedRoutes) but no resources (e.g., unresolved refs).
		for gw, ar := range attachedRoutes {
			if _, ok := seen[gw]; ok {
				continue
			}
			// ensure an entry with just the counts
			results = append(results, toResourceWithRoutes(gw, []*api.Resource{}, ar, rm))
			fmt.Printf("DEBUG: ensure ADPResourcesForGateway for gw=%s/%s with only attachedRoutes=%v\n",
				gw.Namespace, gw.Name, ar)
		}
		allParents := make(map[types.NamespacedName]struct{})
		for _, p := range parentRefs {
			if p.ParentKey.Kind != wellknown.GatewayGVK {
				continue
			}
			gw := types.NamespacedName{Namespace: p.ParentKey.Namespace, Name: p.ParentKey.Name}
			allParents[gw] = struct{}{}
		}

		for gw := range allParents {
			if _, ok := seen[gw]; ok {
				continue
			}
			// attachedRoutes may be nil here; that’s fine — the status normalizer sets zeros.
			results = append(results, toResourceWithRoutes(gw, []*api.Resource{}, attachedRoutes[gw], rm))
			fmt.Printf("DEBUG: ensure ADPResourcesForGateway for gw=%s/%s (no resources; counts=%v)\n", gw.Namespace, gw.Name, attachedRoutes[gw])
		}
		return results
	}, krtopts.ToOptions(collectionName)...)
}

// createTCPRouteCollection is a generic helper function that creates a KRT collection for any route type
// by extracting the common logic shared between TCP and TLS route collections
func createTCPRouteCollection[T controllers.Object](
	routeCol krt.Collection[T],
	inputs RouteContextInputs,
	krtopts krtinternal.KrtOptions,
	plugins pluginsdk.Plugin,
	collectionName string,
	translator func(ctx RouteContext, obj T, rep reporter.Reporter) (RouteContext, iter.Seq2[ADPTCPRoute, *reporter.RouteCondition]),
) krt.Collection[ADPResourcesForGateway] {
	return krt.NewManyCollection(routeCol, func(krtctx krt.HandlerContext, obj T) []ADPResourcesForGateway {
		logger.Debug("translating route", "route_name", obj.GetName(), "resource_version", obj.GetResourceVersion())

		ctx := inputs.WithCtx(krtctx)
		rm := reports.NewReportMap()
		rep := reports.NewReporter(&rm)
		routeReporter := rep.Route(obj)

		// Apply route-specific preprocessing and get the translator
		ctx, translatorSeq := translator(ctx, obj, rep)

		parentRefs, gwResult := computeRoute(ctx, obj, func(obj T) iter.Seq2[ADPTCPRoute, *reporter.RouteCondition] {
			return translatorSeq
		})
		fmt.Printf("DEBUG: route %s/%s parents=%d\n", obj.GetNamespace(), obj.GetName(), len(parentRefs))
		for i, p := range parentRefs {
			fmt.Printf("DEBUG:   [%d] gw=%s/%s section=%q internalName=%q\n",
				i,
				p.ParentKey.Namespace, p.ParentKey.Name,
				string(p.ParentSection), p.InternalName)
		}

		// gateway -> section name -> route count
		routeNN := types.NamespacedName{Namespace: obj.GetNamespace(), Name: obj.GetName()}
		allParentGWs := make(map[types.NamespacedName]struct{})
		for _, p := range parentRefs {
			if p.ParentKey.Kind != wellknown.GatewayGVK {
				continue
			}
			gw := types.NamespacedName{Namespace: p.ParentKey.Namespace, Name: p.ParentKey.Name}
			allParentGWs[gw] = struct{}{}
		}

		// 2) collect all referenced listeners per GW (allowed or not)
		ln := listenersPerGateway(parentRefs)
		allowedParents := filteredReferences(parentRefs)
		attachedRoutes := buildAttachedRoutesMapAllowed(allowedParents, routeNN)
		ensureZeroes(attachedRoutes, ln)
		resourcesPerGateway := processParentReferences[ADPTCPRoute](
			parentRefs,
			gwResult,
			types.NamespacedName{Namespace: obj.GetNamespace(), Name: obj.GetName()}, // was obj.GetName()
			routeReporter,
			func(e ADPTCPRoute, parent routeParentReference) *api.Resource {
				// TCP route wrapper doesn't expose a `Route` field like HTTP.
				// For TCP we don’t mutate ListenerKey/Key here; just pass through.
				return toADPResource(e)
			},
		)

		var results []ADPResourcesForGateway
		seen := make(map[types.NamespacedName]struct{})
		for gw, res := range resourcesPerGateway {
			var ar map[string]uint
			if attachedRoutes[gw] != nil {
				ar = attachedRoutes[gw]
			}
			results = append(results, toResourceWithRoutes(gw, res, ar, rm))
			seen[gw] = struct{}{}
			fmt.Printf("DEBUG: emit gw=%s/%s resources=%d attachedRoutes=%v\n",
				gw.Namespace, gw.Name, len(res), ar)
		}
		for gw, ar := range attachedRoutes {
			if _, ok := seen[gw]; ok {
				continue
			}
			results = append(results, toResourceWithRoutes(gw, []*api.Resource{}, ar, rm))
			fmt.Printf("DEBUG: emit (no resources) gw=%s/%s attachedRoutes=%v\n",
				gw.Namespace, gw.Name, ar)
		}
		return results
	}, krtopts.ToOptions(collectionName)...)
}

// listenersPerGateway returns the set of listener sectionNames referenced for each parent Gateway,
// regardless of whether they are allowed.
func listenersPerGateway(parentRefs []routeParentReference) map[types.NamespacedName]map[string]struct{} {
	l := make(map[types.NamespacedName]map[string]struct{})
	for _, p := range parentRefs {
		if p.ParentKey.Kind != wellknown.GatewayGVK {
			continue
		}
		gw := types.NamespacedName{Namespace: p.ParentKey.Namespace, Name: p.ParentKey.Name}
		if l[gw] == nil {
			l[gw] = make(map[string]struct{})
		}
		l[gw][string(p.ParentSection)] = struct{}{}
	}
	return l
}

// ensureZeroes pre-populates attachedRoutes with explicit 0 entries for every referenced listener,
// so writers that "replace" rather than "merge" will correctly set zero.
func ensureZeroes(
	attached map[types.NamespacedName]map[string]uint,
	ln map[types.NamespacedName]map[string]struct{},
) {
	for gw, set := range ln {
		if attached[gw] == nil {
			attached[gw] = make(map[string]uint)
		}
		for lis := range set {
			if _, ok := attached[gw][lis]; !ok {
				attached[gw][lis] = 0
			}
		}
	}
}

type conversionResult[O any] struct {
	error  *reporter.RouteCondition
	routes []O
}

// IsNil works around comparing generic types
func IsNil[O comparable](o O) bool {
	var t O
	return o == t
}

func newAgentGatewayPasses(plugs pluginsdk.Plugin,
	rep reporter.Reporter,
	aps pluginsdkir.AttachedPolicies) []agwir.AgentGatewayTranslationPass {
	var out []agwir.AgentGatewayTranslationPass
	if len(aps.Policies) == 0 {
		return out
	}
	for gk, paList := range aps.Policies {
		plugin, ok := plugs.ContributesPolicies[gk]
		if !ok || plugin.NewAgentGatewayPass == nil {
			continue
		}
		// only instantiate if there is at least one attached policy
		// OR this is the synthetic built-in GK
		if len(paList) == 0 && gk != pluginsdkir.VirtualBuiltInGK {
			continue
		}
		out = append(out, plugin.NewAgentGatewayPass(rep))
	}
	return out
}

// computeRoute holds the common route building logic shared amongst all types
func computeRoute[T controllers.Object, O comparable](ctx RouteContext, obj T, translator func(
	obj T,
) iter.Seq2[O, *reporter.RouteCondition],
) ([]routeParentReference, conversionResult[O]) {
	parentRefs := extractParentReferenceInfo(ctx, ctx.RouteParents, obj)

	convertRules := func() conversionResult[O] {
		res := conversionResult[O]{}
		for vs, err := range translator(obj) {
			// This was a hard error
			if err != nil && IsNil(vs) {
				res.error = err
				return conversionResult[O]{error: err}
			}
			// Got an error but also routes
			if err != nil {
				res.error = err
			}
			res.routes = append(res.routes, vs)
		}
		return res
	}
	gwResult := buildGatewayRoutes(convertRules)

	return parentRefs, gwResult
}

// RouteContext defines a common set of inputs to a route collection for agentgateway.
// This should be built once per route translation and not shared outside of that.
// The embedded RouteContextInputs is typically based into a collection, then translated to a RouteContext with RouteContextInputs.WithCtx().
type RouteContext struct {
	Krt krt.HandlerContext
	RouteContextInputs
	AttachedPolicies pluginsdkir.AttachedPolicies
	pluginPasses     []agwir.AgentGatewayTranslationPass
}

type RouteContextInputs struct {
	Grants          ReferenceGrants
	RouteParents    RouteParents
	Services        krt.Collection[*corev1.Service]
	InferencePools  krt.Collection[*inf.InferencePool]
	Namespaces      krt.Collection[*corev1.Namespace]
	ServiceEntries  krt.Collection[*networkingclient.ServiceEntry]
	Backends        *krtcollections.BackendIndex
	Policies        *krtcollections.PolicyIndex
	Plugins         pluginsdk.Plugin
	DirectResponses krt.Collection[*v1alpha1.DirectResponse]
}

func (i RouteContextInputs) WithCtx(krtctx krt.HandlerContext) RouteContext {
	return RouteContext{
		Krt:                krtctx,
		RouteContextInputs: i,
	}
}

type RouteWithKey struct {
	*Config
	Key string
}

func (r RouteWithKey) ResourceName() string {
	return config.NamespacedName(r.Config).String()
}

func (r RouteWithKey) Equals(o RouteWithKey) bool {
	return r.Config.Equals(o.Config)
}

// buildGatewayRoutes contains common logic to build a set of routes with gwv1beta1 semantics
func buildGatewayRoutes[T any](convertRules func() T) T {
	return convertRules()
}

// attachRoutePolicies populates ctx.AttachedPolicies with policies that
// target the given HTTPRoute. It uses the exported LookupTargetingPolicies
// from PolicyIndex.
func attachRoutePolicies(ctx *RouteContext, route *gwv1.HTTPRoute) {
	if ctx.Backends == nil {
		return
	}
	pi := ctx.Backends.PolicyIndex()
	if pi == nil {
		return
	}

	target := pluginsdkir.ObjectSource{
		Group:     wellknown.HTTPRouteGVK.Group,
		Kind:      wellknown.HTTPRouteGVK.Kind,
		Namespace: route.Namespace,
		Name:      route.Name,
	}

	pols := pi.LookupTargetingPolicies(ctx.Krt,
		pluginsdk.RouteAttachmentPoint,
		target,
		"", // route-level
		route.GetLabels())

	aps := pluginsdkir.AttachedPolicies{Policies: map[schema.GroupKind][]pluginsdkir.PolicyAtt{}}
	for _, pa := range pols {
		a := aps.Policies[pa.GroupKind]
		aps.Policies[pa.GroupKind] = append(a, pa)
	}

	if _, ok := aps.Policies[pluginsdkir.VirtualBuiltInGK]; !ok {
		aps.Policies[pluginsdkir.VirtualBuiltInGK] = nil
	}
	ctx.AttachedPolicies = aps
}
