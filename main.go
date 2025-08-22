// main.go
package main

import (
	_ "embed"
	"github.com/getlantern/systray"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
)

//go:embed asserts/def.ico
var defIco []byte

//go:embed asserts/tun.ico
var tunIco []byte

//go:embed asserts/system_proxy.ico
var systemProxyIco []byte

// ProxyState holds the current state of the application's proxy settings.
type ProxyState struct {
	SystemProxyEnabled bool
	TunEnabled         bool
	NeedExit           bool // A flag to differentiate between abnormal exit and intentional restart
	mu                 sync.RWMutex
}

// Serv manages the state of the serv.exe child process.
type Serv struct {
	ServCmd     *exec.Cmd
	ServPID     int
	ServSign    chan error
	LogFile     *os.File
	mu          sync.RWMutex
	stopMonitor chan struct{}
}

// Global state variables
var (
	proxyState = loadStateRegistry()
	serv       = &Serv{
		stopMonitor: make(chan struct{}),
	}
	proxyAddr string
)

// cleanup handles the graceful shutdown of the application.
// It restores the system proxy, stops the child process, and saves the state.
func cleanup(isExitFlag bool) {
	// Stop the child process
	stopServ()
	//log.Println("Cleanup complete. Need to exit:", isExitFlag)
	if isExitFlag {
		systray.Quit()
	}
}

// build tag -ldflags "-w -s -H=windowsgui"
func main() {
	// Initial start of the service based on saved state
	startServ(proxyState.TunEnabled)

	// Set up signal handling for graceful shutdown (e.g., Ctrl+C in console)
	mainSign := make(chan os.Signal, 1)
	signal.Notify(mainSign, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	// Goroutine to listen for shutdown signals from the child process or the OS
	go func() {
		select {
		case err := <-serv.ServSign:
			log.Printf("Child process signal received: %v\n", err)
			// If NeedExit is true, it means a restart was intended, so we don't quit.
			// Otherwise, it was an unexpected crash, so we clean up and potentially quit.
			cleanup(!proxyState.NeedExit)
		case sig := <-mainSign:
			log.Printf("OS signal received: %s\n", sig)
			cleanup(true)
		}
	}()

	log.Printf("Lite Mihomo Proxy 已启动\n")

	// Run the system tray icon
	systray.Run(onReady, onExit)
}
