package antivm

import (
	"github.com/StackExchange/wmi"
	"golang.org/x/sys/windows/registry"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"git-malw/internal/utils"
)

type VMDetector struct {
	winapi        *utils.WinAPI
	badFileNames  []string
	badDirs       []string
	badDrivers    []string
	anyRunUUIDs   []string
	kvmDrivers    []string
}

func New() *VMDetector {
	return &VMDetector{
		winapi: utils.NewWinAPI(),
		badFileNames: []string{
			"VBoxMouse.sys", "VBoxGuest.sys", "VBoxSF.sys",
			"VBoxVideo.sys", "vmmouse.sys", "vboxogl.dll",
			"vmhgfs.sys", "vmscsi.sys", "vmci.sys",
			"vmusb.sys", "vmxnet.sys", "vmx_svga.sys", "vmxnet3.sys",
			"hv_vmbus.sys", "hv_storvsc.sys", "hv_netvsc.sys", "hv_balloon.sys",
			"hv_kvp.sys", "hv_fcopy.sys", "hv_vss.sys", "hv_rdv.sys",
			"hv_utils.sys", "hv_ide.sys", "hv_serial.sys", "hv_socket.sys",
			"hv_shutdown.sys", "hv_acpi.sys", "hv_pci.sys", "hv_time.sys",
			"hv_heartbeat.sys", "hv_keyboard.sys", "hv_mouse.sys", "hv_dxgkrnl.sys",
		},
		badDirs: []string{
			`C:\Program Files\VMware`,
			`C:\Program Files\oracle\virtualbox guest additions`,
		},
		badDrivers: []string{
			"balloon.sys", "netkvm.sys", "vioinput",
			"viofs.sys", "vioser.sys", "qemu-ga",
			"qemuwmi", "prl_sf", "prl_tg", "prl_eth",
		},

		 kvmDrivers: []string{"balloon.sys", "netkvm.sys", "vioinput.sys", "viofs.sys", "vioser.sys"},



		anyRunUUIDs: []string{
			"bb926e54-e3ca-40fd-ae90-2764341e7792",
			"90059c37-1320-41a4-b58d-2b75a9850d2f",
		},
	}
}

func (v *VMDetector) getSystem32Path() string {
	systemDir := os.Getenv("SYSTEMROOT")
	if systemDir == "" {
		systemDir = `C:\Windows`
	}
	return filepath.Join(systemDir, "System32")
}

func (v *VMDetector) CheckDisplayRefreshRate() (bool, error) {
	refreshRate, err := v.winapi.GetDisplayRefreshRate()
	if err != nil {
		return false, err
	}
	//println(refreshRate)
	return refreshRate < 29, nil
}



func (v *VMDetector) CheckVMware() (bool, error) {
	var videoControllers []struct{ Name string }
	err := wmi.Query("SELECT Name FROM Win32_VideoController", &videoControllers)
	if err != nil {
		return false, err
	}

	for _, controller := range videoControllers {
		if strings.Contains(strings.ToLower(controller.Name), "vmware") {
			return true, nil
		}
	}
	return false, nil
}

func (v *VMDetector) CheckVirtualBox() (bool, error) {
	var videoControllers []struct{ Name string }
	err := wmi.Query("SELECT Name FROM Win32_VideoController", &videoControllers)
	if err != nil {
		return false, err
	}

	for _, controller := range videoControllers {
		if strings.Contains(strings.ToLower(controller.Name), "virtualbox") {
			return true, nil
		}
	}
	return false, nil
}


/*
func (v *VMDetector) CheckKVM() (bool, error) {
	for _, driver := range v.badDrivers[:5] {
		files, err := filepath.Glob(filepath.Join(v.getSystem32Path(), driver))
		if err != nil {
			continue
		}
		if len(files) > 0 {
			return true, nil
		}
	}
	return false, nil
}*/



/*
func (v *VMDetector) CheckQEMU() (bool, error) {
	files, err := os.ReadDir(v.getSystem32Path())
	if err != nil {
		return false, err
	}

	for _, file := range files {
		for _, driver := range v.badDrivers[5:7] {
			if strings.Contains(file.Name(), driver) {
				return true, nil
			}
		}
	}
	return false, nil
}*/



func (v *VMDetector) CheckQEMU() (bool, error) {
    // Check for QEMU Guest Agent executable
    qemuPaths := []string{
        `C:\Program Files\qemu-ga\qemu-ga.exe`,
        `C:\Program Files (x86)\qemu-ga\qemu-ga.exe`,
        filepath.Join(v.getSystem32Path(), "qemu-ga.exe"),
    }
    
    for _, path := range qemuPaths {
        if _, err := os.Stat(path); err == nil {
            return true, nil
        }
    }
    return false, nil
}













func (v *VMDetector) CheckKVM() (bool, error) {




	// Check WMI for QEMU/KVM identifiers
	var computerSystem []struct{ 
		Manufacturer string
		Model string
	}
	err := wmi.Query("SELECT Manufacturer, Model FROM Win32_ComputerSystem", &computerSystem)
	if err == nil && len(computerSystem) > 0 {
		manufacturer := strings.ToLower(computerSystem[0].Manufacturer)
		model := strings.ToLower(computerSystem[0].Model)
		//println(manufacturer)
		//println(model)


		if strings.Contains(manufacturer, "qemu") || 
		   strings.Contains(model, "qemu") ||
		   strings.Contains(manufacturer, "kvm") {
			//println("mafcat ")
			return true, nil
		}
	}

	// Check BIOS
	var bios []struct{ 
		Manufacturer string
		SerialNumber string
	}
	err = wmi.Query("SELECT Manufacturer, SerialNumber FROM Win32_BIOS", &bios)
	if err == nil && len(bios) > 0 {
		manufacturer := strings.ToLower(bios[0].Manufacturer)
		println(manufacturer)
		if strings.Contains(manufacturer, "qemu") || 
		   strings.Contains(manufacturer, "kvm") {
			println("got bois")
			return true, nil
		}
	}



	// Check for virtio drivers (recursive search)
	driverStorePath := filepath.Join(v.getSystem32Path(), "DriverStore", "FileRepository")

	// Look for VirtIO driver directories
	entries, err := os.ReadDir(driverStorePath)
	if err == nil {
    	for _, entry := range entries {
        	if entry.IsDir() {
            	dirName := strings.ToLower(entry.Name())
            	for _, driver := range v.kvmDrivers {
                	// Convert driver.sys to driver.inf
                	infName := strings.TrimSuffix(strings.ToLower(driver), ".sys") + ".inf"
                
                // Check if directory name starts with driver INF name
                	if strings.HasPrefix(dirName, infName) {
						println(dirName)
                    	return true, nil
                	}
            	}
        	}
    	}
	}


	driversPath := filepath.Join(v.getSystem32Path(), "drivers")
    driverFiles, err := os.ReadDir(driversPath)
    if err == nil {
        //kvmDrivers := []string{"balloon.sys", "netkvm.sys", "vioinput.sys", "viofs.sys", "vioser.sys"}
        
        for _, file := range driverFiles {
            name := strings.ToLower(file.Name())
            for _, driver := range v.kvmDrivers {
                if name == strings.ToLower(driver) {
                    return true, nil
                }
            }
        }
    }




	files, err := os.ReadDir(v.getSystem32Path())
	if err == nil {
		for _, file := range files {
    	fileName := strings.ToLower(file.Name())
    		for _, driver := range v.kvmDrivers {
        		if strings.Contains(fileName, driver) {
            		return true, nil
        		}
   	 		}	
		}
	}


	return false, nil
}










func (v *VMDetector) CheckParallels() (bool, error) {
	files, err := os.ReadDir(v.getSystem32Path())
	if err != nil {
		return false, err
	}

	for _, file := range files {
		for _, driver := range v.badDrivers[7:] {
			if strings.Contains(file.Name(), driver) {
				return true, nil
			}
		}
	}
	return false, nil
}

func (v *VMDetector) CheckVMFiles() bool {
	files, err := os.ReadDir(v.getSystem32Path())
	if err == nil {
		for _, file := range files {
			fileName := strings.ToLower(file.Name())
			for _, badFile := range v.badFileNames {
				if fileName == strings.ToLower(badFile) {
					return true
				}
			}
		}
	}

	for _, badDir := range v.badDirs {
		if _, err := os.Stat(strings.ToLower(badDir)); err == nil {
			return true
		}
	}
	return false
}

// credits to baum1810;
// https://github.com/baum1810/vmdetection/blob/main/vmdetect.bat
func (v *VMDetector) CheckPortConnectors() (bool, error) {
	var portConnectors []struct{ Tag string }
	err := wmi.Query("SELECT * FROM Win32_PortConnector", &portConnectors)
	if err != nil {
		return false, err
	}
	return len(portConnectors) == 0, nil
}




func (v *VMDetector) CheckScreenSize() (bool, error) {
	getSystemMetrics := syscall.NewLazyDLL("user32.dll").NewProc("GetSystemMetrics")
	width, _, err := getSystemMetrics.Call(0)
	if err != nil && err.Error() != "The operation completed successfully." {
		return false, err
	}
	height, _, err := getSystemMetrics.Call(1)
	if err != nil && err.Error() != "The operation completed successfully." {
		return false, err
	}
	//println(width)
	//println(height)


	return width < 800 || height < 600, nil
}





func (v *VMDetector) CheckAnyRun() bool {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer key.Close()

	machineGuid, _, err := key.GetStringValue("MachineGuid")
	if err != nil {
		return false
	}

	for _, uuid := range v.anyRunUUIDs {
		if uuid == machineGuid {
			return true
		}
	}
	return false
}

func (v *VMDetector) CheckUSBDevices() (bool, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\ControlSet001\Services\USBSTOR`, registry.QUERY_VALUE)
	if err == nil {
		defer key.Close()
		return true, nil
	}
	
	key, err = registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\ControlSet001\Enum\USBSTOR`, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return false, nil
	}
	defer key.Close()
	
	subKeys, err := key.ReadSubKeyNames(0)
	if err != nil {
		return false, err
	}
	return len(subKeys) > 0, nil
}

// im not fan of this one, but its a good way to check if the user is a sandboxed user. 
// con: if regular user has a blacklisted username, it will be detected as a sandboxed user.
func (v *VMDetector) CheckBlacklistedUsernames() bool {
	blacklistedNames := []string{
		"Johnson", "Miller", "malware", "maltest", "CurrentUser", "Sandbox", 
		"virus", "John Doe", "test user", "sand box", "WDAGUtilityAccount",
		"Bruno", "george", "Harry Johnson",
	}
	
	username := strings.ToLower(os.Getenv("USERNAME"))
	for _, name := range blacklistedNames {
		if username == strings.ToLower(name) {
			return true
		}
	}
	return false
}

func (v *VMDetector) CheckSandboxie() bool {
	handle := v.winapi.GetModuleHandle("SbieDll.dll")
	return handle != 0
}

func (v *VMDetector) CheckComodoSandbox() bool {
	handle32 := v.winapi.GetModuleHandle("cmdvrt32.dll")
	handle64 := v.winapi.GetModuleHandle("cmdvrt64.dll")
	return handle32 != 0 || handle64 != 0
}

func (v *VMDetector) CheckQihoo360Sandbox() bool {
	handle := v.winapi.GetModuleHandle("SxIn.dll")
	return handle != 0
}

func (v *VMDetector) CheckCuckooSandbox() bool {
	handle := v.winapi.GetModuleHandle("cuckoomon.dll")
	return handle != 0
}

func (v *VMDetector) CheckWine() bool {
	moduleHandle := v.winapi.GetModuleHandle("kernel32.dll")
	if moduleHandle == 0 {
		return false
	}
	
	procAddr := v.winapi.GetProcAddress(moduleHandle, "wine_get_unix_file_name")
	return procAddr != 0
}

func (v *VMDetector) CheckNamedPipes() bool {
	suspiciousDevices := []string{
		"\\\\.\\pipe\\cuckoo",
		"\\\\.\\HGFS",
		"\\\\.\\vmci",
		"\\\\.\\VBoxMiniRdrDN",
		"\\\\.\\VBoxGuest",
		"\\\\.\\pipe\\VBoxMiniRdDN",
		"\\\\.\\VBoxTrayIPC",
		"\\\\.\\pipe\\VBoxTrayIPC",
		"\\\\.\\pipe\\sandbox",
		"\\\\.\\pipe\\vmware",
		"\\\\.\\pipe\\vbox",
		"\\\\.\\pipe\\qemu",
		"\\\\.\\pipe\\analysis",
		"\\\\.\\pipe\\debug",
		"\\\\.\\pipe\\monitor",
	}

	for _, device := range suspiciousDevices {
		file := v.winapi.Fopen(device, "r")
		if file != 0 {
			v.winapi.Fclose(file)
			return true
		}
	}
	return false
}


