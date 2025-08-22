// registry.go
package main

import (
	"golang.org/x/sys/windows/registry"
	"log"
)

const registryPath = `Software\LiteMihomoProxy`

// setSystemProxy enables or disables the Windows system proxy.
func setSystemProxy(addr string) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Internet Settings`,
		registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer func() { _ = k.Close() }()

	if addr == "" {
		if err := k.SetDWordValue("ProxyEnable", 0); err != nil {
			return err
		}
		//log.Println("System proxy disabled.")
	} else {
		if err := k.SetDWordValue("ProxyEnable", 1); err != nil {
			return err
		}
		if err := k.SetStringValue("ProxyServer", addr); err != nil {
			return err
		}
		//log.Println("System proxy set to:", addr)
	}
	return nil
}

// saveStateRegistry saves the application's current state to the registry.
func saveStateRegistry(state *ProxyState) {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, registryPath, registry.SET_VALUE)
	if err != nil {
		log.Printf("Error opening registry key for saving state: %v\n", err)
		return
	}
	defer func() { _ = k.Close() }()

	_ = k.SetDWordValue("SystemProxyEnabled", boolToDWORD(state.SystemProxyEnabled))
	_ = k.SetDWordValue("TunEnabled", boolToDWORD(state.TunEnabled))
	//log.Println("Application state saved to registry.")
}

// loadStateRegistry loads the application's last saved state from the registry.
func loadStateRegistry() *ProxyState {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, registryPath, registry.QUERY_VALUE)
	if err != nil {
		log.Printf("Could not open registry key; using default state. Error: %v\n", err)
		return &ProxyState{} // Return default state
	}
	defer func() { _ = k.Close() }()

	sp, _, _ := k.GetIntegerValue("SystemProxyEnabled")
	tun, _, _ := k.GetIntegerValue("TunEnabled")

	//log.Println("Loaded state from registry.")
	return &ProxyState{
		SystemProxyEnabled: sp != 0,
		TunEnabled:         tun != 0,
	}
}

// boolToDWORD converts a boolean to a DWORD (uint32) for the registry.
func boolToDWORD(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}
