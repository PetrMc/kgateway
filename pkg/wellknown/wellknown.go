// pkg/wellknown/wellknown.go
package wellknown

import (
	internal "github.com/kgateway-dev/kgateway/v2/internal/kgateway/wellknown"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Re-exported values for use in enterprise
var (
	ServiceEntryGVK = internal.ServiceEntryGVK
	HostnameGVK     = internal.HostnameGVK
)

// To confirm if needed to re-export GVKs as GroupKind
func ServiceEntryGroupKind() schema.GroupKind {
	return ServiceEntryGVK.GroupKind()
}
