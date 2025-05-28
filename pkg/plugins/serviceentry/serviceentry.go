// pkg/plugins/serviceentry.go
package serviceentry

import (
	"context"

	"github.com/kgateway-dev/kgateway/v2/internal/kgateway/extensions2/common"
	extensionsplug "github.com/kgateway-dev/kgateway/v2/pkg/pluginsdk"
	internal "github.com/kgateway-dev/kgateway/v2/internal/kgateway/extensions2/plugins/serviceentry"
)

// NewServiceEntryPlugin re-exports the OSS plugin constructor
func NewServiceEntryPlugin(ctx context.Context, col *common.CommonCollections) extensionsplug.Plugin {
	return internal.NewPlugin(ctx, col)
}
