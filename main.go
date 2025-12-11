// main.go
package main

import (
	_ "embed"
	"github.com/getlantern/systray"
	"github.com/shirou/gopsutil/process"
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

func isRunning() bool {
	//currProcPid := int32(os.Process{}.Pid)
	//currProc, _ := process.NewProcess(currProcPid)
	//currProcName, _ := currProc.Name()
	//fmt.Printf("当前PID: %d, 当前进程名: %s\n", currProcPid, currProcName)
	procList, _ := process.Processes()
	for _, proc := range procList {
		name, _ := proc.Name()
		//fmt.Printf("PID: %d, 进程名: %s\n", proc.Pid, name)
		if name == "serv_core.exe" {
			return true
		}
	}
	return false
}

// build tag -ldflags "-w -s -H=windowsgui"
func main() {
	if isRunning() {
		log.Println("已运行。。。")
		return
	}
	// Initial start of the service based on saved state
	if !startServ(proxyState.TunEnabled) {
		return
	}

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
