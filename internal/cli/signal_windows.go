//go:build windows

package cli

import "context"

// signalReload будит живой процесс событием. Если трея нет, ошибка
// проглатывается: add уже записал конфиг, демон прочитает его при старте.
func signalReload(context.Context, Runner) {
	_ = signalEvent(eventReload)
}
