package endpoints

import (
    endpointsinternal "github.com/kgateway-dev/kgateway/v2/internal/kgateway/endpoints"
    krtinternal "github.com/kgateway-dev/kgateway/v2/internal/kgateway/krtcollections"
)

// Re-export the endpoints types that plugins need
type EndpointsInputs = endpointsinternal.EndpointsInputs
type PriorityInfo = endpointsinternal.PriorityInfo
type Prioritizer = endpointsinternal.Prioritizer

// Re-export useful functions
var NewPriorities = endpointsinternal.NewPriorities
var PrioritizeEndpoints = endpointsinternal.PrioritizeEndpoints

// Re-export the krtcollections types for backward compatibility
type EndpointsSettings = krtinternal.EndpointsSettings