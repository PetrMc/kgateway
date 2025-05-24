package waypoint

import (
	"context"
	"log"

	"github.com/kgateway-dev/kgateway/v2/internal/kgateway/extensions2/common"
	"github.com/kgateway-dev/kgateway/v2/internal/kgateway/extensions2/plugins/waypoint"
	extensionsplug "github.com/kgateway-dev/kgateway/v2/pkg/pluginsdk"
)

// NewPlugin exposes the internal Waypoint plugin for use by Enterprise
func NewPlugin(ctx context.Context, commoncol *common.CommonCollections) extensionsplug.Plugin {
	log.Println("[WAYPOINT-PLUGIN] NewPlugin invoked")
	return waypoint.NewPlugin(ctx, commoncol)
}
