// tray.go
package main

import (
	"github.com/getlantern/systray"
	"log"
)

// onReady is called when the system tray is ready. It sets up the icon and menu.
func onReady() {
	systray.SetTitle("Lite Mihomo Proxy")
	updateIcon()

	mIsSystemProxy := systray.AddMenuItemCheckbox("系统代理", "勾选以启用系统代理", proxyState.SystemProxyEnabled)
	mIsTun := systray.AddMenuItemCheckbox("Tun模式", "勾选以启用Tun接口", proxyState.TunEnabled)
	systray.AddSeparator()
	mServRestart := systray.AddMenuItem("重启内核", "重启内核")
	mQuit := systray.AddMenuItem("退出", "退出程序")

	// Main UI event loop
	go func() {
		for {
			select {
			case <-mIsSystemProxy.ClickedCh:
				handleSystemProxyClick(mIsSystemProxy)
			case <-mIsTun.ClickedCh:
				handleTunClick(mIsTun)
			case <-mServRestart.ClickedCh:
				handleRestartClick()
			case <-mQuit.ClickedCh:
				cleanup(true)
				return // Exit the goroutine
			}
		}
	}()
}

// onExit is called when the application is about to quit.
func onExit() {
	// Restore system proxy
	log.Println("清除系统代理...")
	_ = setSystemProxy("")
	// Save current state to registry
	log.Println("保存代理配置...")
	saveStateRegistry(proxyState)
}

// updateIcon sets the systray icon and tooltip based on the current proxy state.
func updateIcon() {
	proxyState.mu.RLock()
	defer proxyState.mu.RUnlock()

	if proxyState.TunEnabled {
		systray.SetIcon(tunIco)
		systray.SetTooltip("TUN模式已启用")
	} else if proxyState.SystemProxyEnabled {
		systray.SetIcon(systemProxyIco)
		systray.SetTooltip("系统代理已启用")
	} else {
		systray.SetIcon(defIco)
		systray.SetTooltip("Lite Mihomo Proxy")
	}
}

// --- Event Handlers ---

func handleSystemProxyClick(m *systray.MenuItem) {
	proxyState.mu.Lock()
	proxyState.SystemProxyEnabled = !proxyState.SystemProxyEnabled
	proxyState.NeedExit = false // This is a normal state change, not a restart trigger
	proxyState.mu.Unlock()

	updateIcon()

	if proxyState.SystemProxyEnabled {
		m.Check()
		_ = setSystemProxy(proxyAddr)
	} else {
		m.Uncheck()
		_ = setSystemProxy("")
	}
}

func handleTunClick(m *systray.MenuItem) {
	proxyState.mu.Lock()
	proxyState.TunEnabled = !proxyState.TunEnabled
	proxyState.NeedExit = true // A restart is required for this change
	proxyState.mu.Unlock()

	updateIcon()

	if proxyState.TunEnabled {
		m.Check()
	} else {
		m.Uncheck()
	}
	restartServ(proxyState.TunEnabled)
}

func handleRestartClick() {
	proxyState.mu.Lock()
	proxyState.NeedExit = true // A restart is intended
	proxyState.mu.Unlock()

	restartServ(proxyState.TunEnabled)
}
