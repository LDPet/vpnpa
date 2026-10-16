package cli

import (
	"context"

	"github.com/LDPet/vpnpa/internal/app"
)

// runHooks — то, чем передний план отличается на Windows: контекст отмены
// и привязка живого App к событиям. На Linux это пустышки.
type runHooks struct {
	ctx  context.Context
	stop func()
	bind func(*app.App)
}
