// pkg/plugins/serviceentry.go
package serviceentry

import (
	"context"

	"github.com/kgateway-dev/kgateway/v2/internal/kgateway/extensions2/common"
	internal "github.com/kgateway-dev/kgateway/v2/internal/kgateway/extensions2/plugins/serviceentry"
	extensionsplug "github.com/kgateway-dev/kgateway/v2/pkg/pluginsdk"
)

// NewServiceEntryPlugin re-exports the OSS plugin constructor
func NewServiceEntryPlugin(ctx context.Context, col *common.CommonCollections) extensionsplug.Plugin {
	return internal.NewPlugin(ctx, col)
}

// InitServiceEntryCollections is used by GG Enterprise to embed the plugin
func InitServiceEntryCollections(col *common.CommonCollections) *internal.ServiceEntryPlugin {
	plugin := internal.InitServiceEntryCollections(col)
	return &plugin
}
