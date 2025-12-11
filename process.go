// process.go
package main

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

// 启动核心
func startServ(isTun bool) bool {
	serv.mu.Lock()
	defer serv.mu.Unlock()

	if serv.ServPID != 0 {
		log.Println("serv.exe 已经在运行，先停止")
		//stopServInternal()
	}

	exePath, _ := os.Executable()
	currentPath := filepath.Dir(exePath)

	logPath := filepath.Join(currentPath, "serv.log")
	servExe := filepath.Join(currentPath, "serv_core.exe")
	config := filepath.Join(currentPath, "config.yaml")
	configEnSt, newProxyAddr, _ := parseConfig(isTun, config)

	// 关闭旧的日志文件
	if serv.LogFile != nil {
		err := serv.LogFile.Close()
		if nil != err {
			log.Fatal("日志文件关闭失败!\n", err)
		}
		serv.LogFile = nil
	}
	proxyAddr = newProxyAddr
	if proxyState.SystemProxyEnabled {
		err := setSystemProxy(proxyAddr)
		if err != nil {
			log.Fatal("系统代理设置失败！", err)
		}
	}

	// 创建新的日志文件
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Println("无法创建日志文件:", err)
		return false
	}
	serv.LogFile = logFile

	// 创建命令
	serv.ServCmd = exec.Command(servExe, "-d", currentPath, "-config", configEnSt)
	serv.ServCmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
	}
	serv.ServCmd.Stdout = serv.LogFile
	serv.ServCmd.Stderr = serv.LogFile

	// 启动进程
	if err := serv.ServCmd.Start(); err != nil {
		log.Printf("核心启动失败: %v\n", err)
		err := serv.LogFile.Close()
		if nil != err {
			log.Fatal("日志文件关闭失败!\n", err)
		}
		serv.LogFile = nil
		return false
	}

	serv.ServPID = serv.ServCmd.Process.Pid

	// 创建新的监控通道
	serv.ServSign = make(chan error, 1)

	// 停止旧的监控
	close(serv.stopMonitor)
	serv.stopMonitor = make(chan struct{})

	// 启动新的监控
	go serv.monitorProcess(serv.stopMonitor)

	log.Printf("serv.exe 已启动。 (PID: %d)\n", serv.ServPID)
	log.Printf("日志文件: %s\n", logPath)
	return true
}

// 监控进程
func (s *Serv) monitorProcess(stop chan struct{}) {
	select {
	case err := <-s.ServSign:
		select {
		case <-stop:
			// 正常停止，不处理
			return
		default:
			// 进程异常退出
			log.Printf("serv.exe 异常退出: %v\n", err)
			s.mu.Lock()
			s.ServPID = 0
			s.ServCmd = nil
			s.mu.Unlock()

			// 通知主程序清理
			cleanup(false)
		}
	case <-stop:
		// 正常停止
		return
	}
}

// 内部停止服务（不加锁，由外部函数加锁）
func stopServInternal() {
	if serv.ServCmd != nil && serv.ServCmd.Process != nil {
		log.Printf("正在停止 serv.exe (PID: %d)...\n", serv.ServPID)
		if err := serv.ServCmd.Process.Kill(); err != nil {
			log.Printf("强制终止失败: %v\n", err)
		}
	}

	// 通知监控停止
	select {
	case serv.stopMonitor <- struct{}{}:
	default:
	}

	// 清理资源
	if serv.LogFile != nil {
		err := serv.LogFile.Close()
		if nil != err {
			log.Fatal("日志文件关闭失败!\n", err)
		}
		serv.LogFile = nil
	}

	log.Printf("serv.exe 已停止。\n\n")
	serv.ServCmd = nil
	serv.ServPID = 0
}

// 停止核心
func stopServ() {
	serv.mu.Lock()
	defer serv.mu.Unlock()
	stopServInternal()
}

// 重启核心
func restartServ(isTun bool) {
	log.Println("正在重启 serv.exe...")
	stopServ()
	time.Sleep(300 * time.Millisecond) // 给系统一点时间清理
	startServ(isTun)
}
