//go:build windows

package main

import (
	"os"
	"syscall"
	"unsafe"
)

func init() {
	var mode uint32
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getConsoleMode := kernel32.NewProc("GetConsoleMode")
	setConsoleMode := kernel32.NewProc("SetConsoleMode")

	stdout := syscall.Handle(os.Stdout.Fd())
	getConsoleMode.Call(uintptr(stdout), uintptr(unsafe.Pointer(&mode)))
	setConsoleMode.Call(uintptr(stdout), uintptr(mode|0x4)) // ENABLE_VIRTUAL_TERMINAL_PROCESSING

	stderr := syscall.Handle(os.Stderr.Fd())
	getConsoleMode.Call(uintptr(stderr), uintptr(unsafe.Pointer(&mode)))
	setConsoleMode.Call(uintptr(stderr), uintptr(mode|0x4))
}
